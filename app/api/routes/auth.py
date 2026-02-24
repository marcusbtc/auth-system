from urllib.parse import quote_plus

from fastapi import APIRouter, Cookie, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse

from app.api.deps import auth_service, enforce_csrf, get_bearer_token, get_client_ip
from app.core.config import settings
from app.core.errors import AppError
from app.core.security import generate_csrf_token
from app.models.auth import (
    ActivateRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    MessageResponse,
    RegisterResponse,
    ResetPasswordRequest,
    TokenPair,
)
from app.models.user import RegisterRequest

router = APIRouter(prefix='/api/auth', tags=['auth'])


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str, csrf_token: str) -> None:
    response.set_cookie(
        key='access_token',
        value=access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        max_age=settings.access_token_expire_minutes * 60,
        path='/',
    )
    response.set_cookie(
        key='refresh_token',
        value=refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        max_age=settings.refresh_token_expire_days * 24 * 3600,
        path='/',
    )
    response.set_cookie(
        key='csrf_token',
        value=csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        max_age=settings.refresh_token_expire_days * 24 * 3600,
        path='/',
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie('access_token', domain=settings.cookie_domain, path='/')
    response.delete_cookie('refresh_token', domain=settings.cookie_domain, path='/')
    response.delete_cookie('csrf_token', domain=settings.cookie_domain, path='/')


@router.post('/register', response_model=RegisterResponse)
def register(payload: RegisterRequest):
    return auth_service.register(payload.username, payload.password)


@router.post('/activate', response_model=MessageResponse)
def activate(payload: ActivateRequest, request: Request):
    return auth_service.activate(payload.token, ip_key=get_client_ip(request))


@router.post('/login', response_model=TokenPair)
def login(payload: LoginRequest, request: Request, response: Response):
    tokens = auth_service.login(payload.username, payload.password, ip_key=get_client_ip(request))
    csrf_token = generate_csrf_token()
    tokens['csrf_token'] = csrf_token
    _set_auth_cookies(response, tokens['access_token'], tokens['refresh_token'], csrf_token)
    return tokens


@router.post('/refresh', response_model=TokenPair)
def refresh(
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    refresh_cookie: str | None = Cookie(default=None, alias='refresh_token'),
):
    if not refresh_cookie:
        raise AppError('Refresh token is required', status_code=401, code='UNAUTHORIZED')
    tokens = auth_service.refresh(refresh_cookie, ip_key=get_client_ip(request))
    csrf_token = generate_csrf_token()
    tokens['csrf_token'] = csrf_token
    _set_auth_cookies(response, tokens['access_token'], tokens['refresh_token'], csrf_token)
    return tokens


@router.post('/forgot-password', response_model=ForgotPasswordResponse)
def forgot_password(payload: ForgotPasswordRequest, request: Request):
    return auth_service.forgot_password(payload.username, ip_key=get_client_ip(request))


@router.post('/reset-password', response_model=MessageResponse)
def reset_password(payload: ResetPasswordRequest, request: Request):
    return auth_service.reset_password(payload.token, payload.new_password, ip_key=get_client_ip(request))


@router.post('/logout', response_model=MessageResponse)
def logout(
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    bearer_token: str | None = Depends(get_bearer_token),
    refresh_cookie: str | None = Cookie(default=None, alias='refresh_token'),
    access_cookie: str | None = Cookie(default=None, alias='access_token'),
):
    access_token = bearer_token or access_cookie
    result = auth_service.logout(refresh_cookie, access_token, ip_key=get_client_ip(request))
    _clear_auth_cookies(response)
    return result


@router.post('/web-login')
def web_login(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        tokens = auth_service.login(username, password, ip_key=get_client_ip(request))
    except AppError as exc:
        return RedirectResponse(url=f"/login-page?error={quote_plus(exc.message)}", status_code=302)
    redirect = RedirectResponse(url='/dashboard', status_code=302)
    _set_auth_cookies(redirect, tokens['access_token'], tokens['refresh_token'], generate_csrf_token())
    return redirect


@router.get('/web-logout')
def web_logout(
    request: Request,
    refresh_cookie: str | None = Cookie(default=None, alias='refresh_token'),
    access_cookie: str | None = Cookie(default=None, alias='access_token'),
):
    auth_service.logout(refresh_cookie, access_cookie, ip_key=get_client_ip(request))
    redirect = RedirectResponse(url='/login-page', status_code=302)
    _clear_auth_cookies(redirect)
    return redirect
