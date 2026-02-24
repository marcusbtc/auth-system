from fastapi import APIRouter, Depends, Query, Request

from app.api.deps import enforce_csrf, get_client_ip, get_current_user, require_admin, user_service
from app.models.user import UpdateUserRequest, UserRole, UsersPage

router = APIRouter(prefix='/api/users', tags=['users'])


@router.get('/me')
def me(current_user: dict = Depends(get_current_user)):
    return user_service.get_me(current_user)


@router.get('', response_model=UsersPage)
def list_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=100),
    q: str | None = None,
    role: UserRole | None = None,
    is_active: bool | None = None,
    _: dict = Depends(get_current_user),
):
    return user_service.list_users(page=page, page_size=page_size, query=q, role=role, active=is_active)


@router.put('/{user_id}')
def update_user(
    user_id: str,
    request: Request,
    payload: UpdateUserRequest,
    _: None = Depends(enforce_csrf),
    current_user: dict = Depends(get_current_user),
):
    return user_service.update_user(user_id, payload.model_dump(), current_user, ip_key=get_client_ip(request))


@router.delete('/{user_id}')
def delete_user(
    user_id: str,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: dict = Depends(require_admin),
):
    return user_service.delete_user(user_id, current_user, ip_key=get_client_ip(request))


@router.get('/admin')
def admin_route(current_user: dict = Depends(require_admin)):
    return {'message': f"Welcome admin {current_user['username']}"}
