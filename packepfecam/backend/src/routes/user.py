# from fastapi import APIRouter, Depends, HTTPException, status

# from ..models.user import User, UserResponse, UserUpdate
# from .. import oauth2
# from .. import utils
# from fastapi_jwt_auth import AuthJWT


# router = APIRouter()


# @router.get("/me", response_model=UserResponse)
# async def get_me(user_id: str = Depends(oauth2.require_user)):
#     user = await User.get(str(user_id))
#     r_user = UserResponse(
#         username=user.username,
#         email=user.email,
#         phone_number=user.phone_number,
#         department=user.department,
#         role=user.role,
#     )
#     return r_user


# from fastapi import HTTPException, status


# @router.put("/me/update", response_model=UserResponse)
# async def update_me(
#     user_update: UserUpdate,
#     user_id: str = Depends(oauth2.require_user),
#     Authorize: AuthJWT = Depends(),
# ):
#     user = await User.get(str(user_id))

#     # Update user attributes
#     if user_update.username != user.username:
#         user_exists = await User.find_one(User.username == user_update.username)
#         if user_exists:
#             raise HTTPException(
#                 status_code=status.HTTP_409_CONFLICT,
#                 detail="Username already exists",
#             )
#         user.username = user_update.username
#     if user_update.email != user.email:
#         if not utils.is_valid_email(user_update.email):
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email"
#             )
#         email_exists = await User.find_one(User.email == user_update.email)
#         if email_exists:
#             raise HTTPException(
#                 status_code=status.HTTP_409_CONFLICT,
#                 detail="Email already exists",
#             )
#         old_email = user.email  # Store the old email for logging out
#         user.email = user_update.email
#         verification_code = utils.generate_verification_code()
#         await utils.send_verification_email(user.email, verification_code)
#         user.verification_code = verification_code
#         user.is_verified = False

#         # Log out the user if email is updated
#         Authorize.unset_jwt_cookies()

#     if user_update.phone_number != user.phone_number:
#         if not utils.is_valid_phone_number(user_update.phone_number):
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number"
#             )
#         phone_number_exists = await User.find_one(
#             User.phone_number == user_update.phone_number
#         )
#         if phone_number_exists:
#             raise HTTPException(
#                 status_code=status.HTTP_409_CONFLICT,
#                 detail="Phone number already exists",
#             )
#         user.phone_number = user_update.phone_number

#     user_exists = await User.find_one(User.username == user_update.username)
#     email_exists = await User.find_one(User.email == user_update.email)
#     phone_number_exists = await User.find_one(
#         User.phone_number == user_update.phone_number
#     )
#     # Save the updated user back to the database
#     await user.save()

#     # Return the updated user as a response
#     return UserResponse(
#         username=user.username,
#         email=user.email,
#         phone_number=user.phone_number,
#         department=user.department,
#         role=user.role,
#     )


# @router.put("/me/change-password")
# async def change_password(
#     old_password: str, new_password: str, user_id: str = Depends(oauth2.require_user)
# ):
#     user = await User.get(str(user_id))

#     # Verify the old password
#     if not utils.verify_password(old_password, user.password):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect old password",
#         )

#     # Update the password with the new one
#     user.password = utils.hash_password(new_password)

#     # Save the updated user back to the database
#     await user.save()

#     # Return the updated user as a response
#     return {"status": "password updated successfully"}


# @router.delete(
#     "/me/delete",
# )
# async def delete_me(user_id: str = Depends(oauth2.require_user)):
#     user = await User.get(str(user_id))

#     # Delete the user from the database
#     await user.delete()

#     # Return the deleted user as a response
#     return {"status": "account successfully deleted"}
