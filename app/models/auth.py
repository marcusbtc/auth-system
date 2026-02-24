from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class ActivateRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    username: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=200)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    csrf_token: str
    token_type: str = 'bearer'
    expires_in: int


class MessageResponse(BaseModel):
    message: str


class RegisterResponse(MessageResponse):
    activation_token: str | None = None


class ForgotPasswordResponse(MessageResponse):
    reset_token: str | None = None
