// @flow
import querystring from "querystring";
import fetch from "isomorphic-fetch";
import { InvalidRequestError } from "./errors";

const AUTH0_API_URL = "https://0x11.auth0.com";

export async function post(endpoint: string, body: Object) {
  let data;

  const token = body.token;
  try {
    const response = await fetch(`${AUTH0_API_URL}${endpoint}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    data = await response.json();
  } catch (err) {
    throw new InvalidRequestError(err.message);
  }
  if (!!data.error)
    throw new InvalidRequestError(`${data.error}\n${data.error_description}`);

  return data;
}

export async function request(endpoint: string, body: Object) {
  let data;
  console.log(querystring.stringify(body));
  try {
    const response = await fetch(`${AUTH0_API_URL}${endpoint}`, {
      method: "POST",
      headers: {
        "Content-type": "application/x-www-form-urlencoded; charset=UTF-8",
      },
      body: querystring.stringify(body),
    });
    data = await response.json();
  } catch (err) {
    throw new InvalidRequestError(err.message);
  }
  console.log(data);
  if (!!data.error)
    throw new InvalidRequestError(data.error + data.error_description);

  return data;
}

export async function get(endpoint: string, body: Object) {
  let data;
  const token = body.token;

  try {
    const response = await fetch(
      `${AUTH0_API_URL}${endpoint}?${querystring.stringify(body)}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    data = await response.json();
  } catch (err) {
    throw new InvalidRequestError(err.message);
  }
  if (!!data.error)
    throw new InvalidRequestError(data.error + data.error_description);

  return data;
}

export async function oauthAccess(
  code: string,
  redirect_uri: string = `${process.env.URL || ""}/`
) {
  let token = await request("/oauth/token", {
    client_id: process.env.AUTH0_KEY,
    client_secret: process.env.AUTH0_SECRET,
    grant_type: "authorization_code",
    redirect_uri,
    code,
  });

  let user = await get("/userinfo", {
    token: token.access_token,
  });

  return {
    user: user,
    team: {
      id: "0x11",
      name: "0x11",
      image: "",
      domain: "0x11",
    },
  };
}
