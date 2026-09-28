from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_s3_storage_client
from database import get_db, UserModel, UserProfileModel, UserGroupEnum
from database.models.accounts import GenderEnum
from exceptions import TokenExpiredError, InvalidTokenError, S3FileUploadError
from schemas.profiles import ProfileCreateRequestSchema, ProfileResponseSchema
from security.http import get_token
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface

router = APIRouter(tags=["profiles"])


async def get_current_user_payload(
    token: str = Depends(get_token),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> dict:
    try:
        return jwt_manager.decode_access_token(token)
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")


@router.post("/users/{user_id}/profile/", response_model=ProfileResponseSchema, status_code=201)
async def create_user_profile(
    user_id: int,
    first_name: str = Form(...),
    last_name: str = Form(...),
    gender: str = Form(...),
    date_of_birth: str = Form(...),
    info: str = Form(...),
    avatar: UploadFile = File(...),
    token_payload: dict = Depends(get_current_user_payload),
    db: AsyncSession = Depends(get_db),
    s3_client: S3StorageInterface = Depends(get_s3_storage_client),
):
    current_user_id = token_payload.get("user_id")

    if current_user_id != user_id:
        stmt_current = (
            select(UserModel)
            .options(joinedload(UserModel.group))
            .where(UserModel.id == current_user_id)
        )
        result_current = await db.execute(stmt_current)
        current_user = result_current.scalars().first()

        is_admin = current_user is not None and current_user.has_group(UserGroupEnum.ADMIN)

        if not is_admin:
            raise HTTPException(status_code=403, detail="You don't have permission to edit this profile.")

    stmt = select(UserModel).where(UserModel.id == user_id, UserModel.is_active)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=401, detail="User not found or not active.")

    stmt_profile = select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    result_profile = await db.execute(stmt_profile)
    existing_profile = result_profile.scalars().first()

    if existing_profile:
        raise HTTPException(status_code=400, detail="User already has a profile.")

    try:
        profile_data = ProfileCreateRequestSchema(
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            info=info,
            avatar=avatar,
        )
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    avatar_content = await avatar.read()
    avatar_key = f"avatars/{user_id}_avatar.jpg"

    try:
        await s3_client.upload_file(avatar_key, avatar_content)
    except S3FileUploadError:
        raise HTTPException(status_code=500, detail="Failed to upload avatar. Please try again later.")

    new_profile = UserProfileModel(
        user_id=user_id,
        first_name=profile_data.first_name,
        last_name=profile_data.last_name,
        gender=GenderEnum(profile_data.gender),
        date_of_birth=profile_data.date_of_birth,
        info=profile_data.info,
        avatar=avatar_key,
    )

    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)

    avatar_url = await s3_client.get_file_url(avatar_key)

    return ProfileResponseSchema(
        id=new_profile.id,
        user_id=new_profile.user_id,
        first_name=new_profile.first_name,
        last_name=new_profile.last_name,
        gender=new_profile.gender.value,
        date_of_birth=new_profile.date_of_birth,
        info=new_profile.info,
        avatar=avatar_url,
    )
