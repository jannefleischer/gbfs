## OAuth2 client_credentials helper for GBFS package
# Minimal helper: fetch and cache access token, and a JSON fetch wrapper

gbfs_token_env <- new.env(parent = emptyenv())

# Set global auth values for the package. Call this once to avoid
# passing credentials repeatedly to functions.
set_gbfs_auth <- function(token = NULL, token_url = NULL, client_id = NULL, client_secret = NULL, scope = NULL) {
  if (!is.null(token)) {
    gbfs_token_env$token <- token
    # set a long expiry if user supplied a token (can't know real expiry)
    gbfs_token_env$expires_at <- Sys.time() + 60 * 60 * 24
  }
  if (!is.null(token_url)) gbfs_token_env$token_url <- token_url
  if (!is.null(client_id)) gbfs_token_env$client_id <- client_id
  if (!is.null(client_secret)) gbfs_token_env$client_secret <- client_secret
  if (!is.null(scope)) gbfs_token_env$scope <- scope
  invisible(TRUE)
}

clear_gbfs_auth <- function() {
  rm(list = ls(envir = gbfs_token_env), envir = gbfs_token_env)
  invisible(TRUE)
}

# Obtain an access token. If arguments are NULL, try to read stored
# credentials from `gbfs_token_env` (set via `set_gbfs_auth`).
get_gbfs_token <- function(token_url = NULL, client_id = NULL, client_secret = NULL, scope = NULL, force = FALSE) {
  if (!is.null(gbfs_token_env$token) && !force) {
    if (!is.null(gbfs_token_env$expires_at) && Sys.time() < gbfs_token_env$expires_at) {
      return(gbfs_token_env$token)
    }
  }

  # fallback to stored values if not provided
  if (is.null(token_url) && !is.null(gbfs_token_env$token_url)) token_url <- gbfs_token_env$token_url
  if (is.null(client_id) && !is.null(gbfs_token_env$client_id)) client_id <- gbfs_token_env$client_id
  if (is.null(client_secret) && !is.null(gbfs_token_env$client_secret)) client_secret <- gbfs_token_env$client_secret
  if (is.null(scope) && !is.null(gbfs_token_env$scope)) scope <- gbfs_token_env$scope

  if (is.null(token_url) || is.null(client_id) || is.null(client_secret)) {
    stop("Missing OAuth2 client credentials: set them via set_gbfs_auth() or supply them to get_gbfs_token().")
  }

  resp <- httr::POST(
    url = token_url,
    httr::add_headers(`content-type` = "application/x-www-form-urlencoded"),
    body = list(
      grant_type = "client_credentials",
      client_id = client_id,
      client_secret = client_secret,
      scope = scope
    ),
    encode = "form"
  )

  if (httr::status_code(resp) >= 400) {
    stop(sprintf("Token request failed: %s", httr::content(resp, as = "text", encoding = "UTF-8")))
  }

  body <- httr::content(resp, type = "application/json", encoding = "UTF-8")
  token <- body$access_token
  expires_in <- as.numeric(body$expires_in %||% 3600)

  gbfs_token_env$token <- token
  gbfs_token_env$expires_at <- Sys.time() + expires_in - 30
  token
}

