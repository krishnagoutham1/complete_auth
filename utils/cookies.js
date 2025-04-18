const { COOKIE_AGE, COOKIE_KEY_NAMES } = require("./constants");

const isProduction = process.env.NODE_ENV === "production";

const cookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: isProduction,
  sameSite: "strict",
  maxAge,
});

const setAccessTokenCookie = (res, token) => {
  res.cookie(
    COOKIE_KEY_NAMES.ACCESS_TOKEN,
    token,
    cookieOptions(COOKIE_AGE.ACCESS_TOKEN)
  );
};

const setRefreshIdCookie = (res, refreshId) => {
  res.cookie(
    COOKIE_KEY_NAMES.REFRESH_TOKEN_ID,
    refreshId,
    cookieOptions(COOKIE_AGE.REFRESH_TOKEN_ID)
  );
};

const setUserIdCookie = (res, userId) => {
  res.cookie(
    COOKIE_KEY_NAMES.USER_ID,
    userId,
    cookieOptions(COOKIE_AGE.USER_ID)
  );
};

// Clear All Auth Cookies
const clearAuthCookies = (res) => {
  Object.values(COOKIE_KEY_NAMES).forEach((key) => {
    res.clearCookie(key);
  });
};

module.exports = {
  setAccessTokenCookie,
  setRefreshIdCookie,
  setUserIdCookie,
  clearAuthCookies,
};
