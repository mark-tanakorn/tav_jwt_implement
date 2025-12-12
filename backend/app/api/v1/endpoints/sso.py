"""
SSO Endpoint

Handles Single Sign-On from BizProj using JWT tokens.
"""

import logging
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import RedirectResponse

from app.core.jwt_manager import JwtTokenManager
from app.config import settings

logger = logging.getLogger(_name_)

router = APIRouter(prefix="/sso", tags=["sso"])


@router.get("/", status_code=status.HTTP_200_OK)
def sso_login(
    token: str = Query(..., description="JWT token from BizProj")
) -> RedirectResponse:
    """
    SSO login endpoint.

    Validates JWT token from BizProj and redirects to TAV dashboard if valid.

    Args:
        token: JWT token containing user authentication info

    Returns:
        Redirect to TAV dashboard on success

    Raises:
        HTTPException: If token is invalid
    """
    # Validate the JWT token
    claims = JwtTokenManager.validate_token(token)
    if not claims:
        logger.warning("❌ SSO: Invalid or expired token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired SSO token"
        )

    # Log all claims from the JWT
    logger.info(f"✅ SSO: Token validated successfully")
    logger.info(f"📦 SSO Claims: {claims}")
    logger.info(f"   - sub: {claims.get('sub')}")
    logger.info(f"   - userId: {claims.get('userId')}")
    logger.info(f"   - username: {claims.get('username')}")
    logger.info(f"   - department: {claims.get('department')}")
    logger.info(f"   - role: {claims.get('role')}")

    # Extract user info
    user_id = JwtTokenManager.get_user_id_from_token(token)
    username = JwtTokenManager.get_username_from_token(token)

    logger.info(f"👤 SSO: User ID={user_id}, Username={username}")
    
    if user_id == 0 or not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user data in SSO token"
        )

    # TODO: Implement user session/login logic here
    # For now, just validate and redirect
    # In production, you might:
    # - Check if user exists in TAV DB
    # - Create/update user session
    # - Set authentication cookies
    # - Log the SSO login event

    # Redirect to TAV dashboard (adjust URL as needed)
    dashboard_url = f"{settings.BASE_URL}"
    return RedirectResponse(
        url=dashboard_url,
        status_code=status.HTTP_302_FOUND
    )