from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    admin = 'admin'
    user = 'user'


class UserOut(BaseModel):
    id: str
    username: str
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=200)


class UpdateUserRequest(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=50)
    password: str | None = Field(default=None, min_length=8, max_length=200)
    role: UserRole | None = None
    is_active: bool | None = None


class UsersPage(BaseModel):
    items: list[UserOut]
    page: int
    page_size: int
    total: int
