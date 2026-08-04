from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.api.deps import get_current_user, user_service

templates = Jinja2Templates(directory='templates')
router = APIRouter(tags=['pages'])


@router.get('/', response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request=request, name='index.html')


@router.get('/login-page', response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name='login.html')


@router.get('/register-page', response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name='register.html')


@router.get('/dashboard', response_class=HTMLResponse)
def dashboard(request: Request, current_user: dict = Depends(get_current_user)):
    users_payload = user_service.list_users(page=1, page_size=100, query=None, role=None, active=None)
    return templates.TemplateResponse(
        request=request,
        name='dashboard.html',
        context={'current_user': user_service.users.to_public(current_user), 'users': users_payload['items']},
    )


@router.get('/logout')
def logout_redirect():
    return RedirectResponse(url='/api/auth/web-logout', status_code=302)
