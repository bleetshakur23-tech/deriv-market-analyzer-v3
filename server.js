require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

const CLIENT_ID =
    process.env.DERIV_CLIENT_ID;

const REDIRECT_URI =
    process.env.DERIV_REDIRECT_URI;

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    "development-secret-change-me";

const DERIV_API =
    "https://api.derivws.com";

const AUTH_URL =
    "https://auth.deriv.com/oauth2/auth";

const TOKEN_URL =
    "https://auth.deriv.com/oauth2/token";



/*
========================================================
EXPRESS
========================================================
*/

app.use(
    express.json()
);

app.use(
    express.urlencoded({
        extended: true
    })
);



/*
========================================================
SESSION
========================================================
*/

app.use(
    session({

        secret:
            SESSION_SECRET,

        resave:
            false,

        saveUninitialized:
            false,

        cookie: {

            httpOnly:
                true,

            secure:
                false,

            sameSite:
                "lax",

            maxAge:
                1000 *
                60 *
                60 *
                24

        }

    })
);



/*
========================================================
STATIC WEBSITE
========================================================
*/

app.use(
    express.static(
        path.join(
            __dirname
        )
    )
);



/*
========================================================
HELPERS
========================================================
*/

function base64Url(
    buffer
) {

    return buffer

        .toString("base64")

        .replace(
            /\+/g,
            "-"
        )

        .replace(
            /\//g,
            "_"
        )

        .replace(
            /=+$/,
            ""
        );

}



function randomString(
    bytes = 64
) {

    return base64Url(
        crypto.randomBytes(
            bytes
        )
    );

}



function sha256(
    value
) {

    return crypto
        .createHash("sha256")
        .update(value)
        .digest();

}



/*
========================================================
CHECK CONFIGURATION
========================================================
*/

app.get(
    "/api/config",

    (req, res) => {

        res.json({

            configured:
                Boolean(
                    CLIENT_ID &&
                    REDIRECT_URI
                ),

            clientId:
                CLIENT_ID ||
                null,

            loggedIn:
                Boolean(
                    req.session.deriv
                )

        });

    }
);



/*
========================================================
START LOGIN
========================================================
*/

app.get(
    "/auth/login",

    (req, res) => {

        if (!CLIENT_ID) {

            return res
                .status(500)
                .send(
                    "DERIV_CLIENT_ID is not configured."
                );

        }



        const verifier =
            randomString(64);


        const challenge =
            base64Url(
                sha256(
                    verifier
                )
            );


        const state =
            randomString(32);



        /*
        Store PKCE values in the
        server session.
        */

        req.session.oauth = {

            verifier:
                verifier,

            state:
                state

        };



        const params =
            new URLSearchParams({

                response_type:
                    "code",

                client_id:
                    CLIENT_ID,

                redirect_uri:
                    REDIRECT_URI,

                scope:
                    "trade account_manage",

                state:
                    state,

                code_challenge:
                    challenge,

                code_challenge_method:
                    "S256"

            });



        const url =
            AUTH_URL +
            "?" +
            params.toString();



        res.redirect(
            url
        );

    }
);



/*
========================================================
START SIGN UP
========================================================
*/

app.get(
    "/auth/signup",

    (req, res) => {

        if (!CLIENT_ID) {

            return res
                .status(500)
                .send(
                    "DERIV_CLIENT_ID is not configured."
                );

        }



        const verifier =
            randomString(64);


        const challenge =
            base64Url(
                sha256(
                    verifier
                )
            );


        const state =
            randomString(32);



        req.session.oauth = {

            verifier:
                verifier,

            state:
                state

        };



        const params =
            new URLSearchParams({

                response_type:
                    "code",

                client_id:
                    CLIENT_ID,

                redirect_uri:
                    REDIRECT_URI,

                scope:
                    "trade account_manage",

                state:
                    state,

                code_challenge:
                    challenge,

                code_challenge_method:
                    "S256",

                prompt:
                    "registration"

            });



        res.redirect(

            AUTH_URL +
            "?" +
            params.toString()

        );

    }
);



/*
========================================================
OAUTH CALLBACK
========================================================
*/

app.get(
    "/oauth/callback",

    async (req, res) => {

        try {

            const {
                code,
                state,
                error
            } = req.query;



            if (error) {

                return res
                    .status(400)
                    .send(

                        "Deriv authorization failed: " +
                        error

                    );

            }



            if (!code || !state) {

                return res
                    .status(400)
                    .send(
                        "Missing OAuth code or state."
                    );

            }



            const oauth =
                req.session.oauth;



            if (
                !oauth ||
                !oauth.state ||
                oauth.state !== state
            ) {

                return res
                    .status(400)
                    .send(
                        "Invalid OAuth state."
                    );

            }



            /*
            Exchange authorization code
            for access token.
            */

            const response =
                await fetch(
                    TOKEN_URL,

                    {

                        method:
                            "POST",

                        headers: {

                            "Content-Type":
                                "application/x-www-form-urlencoded"

                        },

                        body:
                            new URLSearchParams({

                                grant_type:
                                    "authorization_code",

                                client_id:
                                    CLIENT_ID,

                                redirect_uri:
                                    REDIRECT_URI,

                                code:
                                    code,

                                code_verifier:
                                    oauth.verifier

                            })

                    }

                );



            const tokenData =
                await response.json();



            if (!response.ok) {

                console.error(
                    "TOKEN ERROR:",
                    tokenData
                );

                return res
                    .status(400)
                    .send(
                        "Could not complete Deriv login."
                    );

            }



            /*
            Store token server-side.

            Never send the OAuth token
            to the browser.
            */

            req.session.deriv = {

                accessToken:
                    tokenData.access_token,

                refreshToken:
                    tokenData.refresh_token ||
                    null,

                expiresIn:
                    tokenData.expires_in ||
                    null

            };



            delete req.session.oauth;



            res.redirect(
                "/?login=success"
            );

        }

        catch (error) {

            console.error(
                error
            );

            res
                .status(500)
                .send(
                    "Authentication error."
                );

        }

    }
);



/*
========================================================
LOGOUT
========================================================
*/

app.post(
    "/api/logout",

    (req, res) => {

        req.session.destroy(
            () => {

                res.json({

                    success:
                        true

                });

            }
        );

    }
);



/*
========================================================
GET ACCOUNTS
========================================================
*/

app.get(
    "/api/accounts",

    async (req, res) => {

        try {

            if (
                !req.session.deriv
            ) {

                return res
                    .status(401)
                    .json({

                        error:
                            "NOT_LOGGED_IN"

                    });

            }



            const response =
                await fetch(

                    DERIV_API +
                    "/trading/v1/options/accounts",

                    {

                        method:
                            "GET",

                        headers: {

                            "Deriv-App-ID":
                                CLIENT_ID,

                            "Authorization":
                                "Bearer " +
                                req.session.deriv
                                    .accessToken

                        }

                    }

                );



            const data =
                await response.json();



            if (!response.ok) {

                console.error(
                    "ACCOUNT ERROR:",
                    data
                );

                return res
                    .status(
                        response.status
                    )
                    .json(data);

            }



            res.json(
                data
            );

        }

        catch (error) {

            console.error(
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Could not retrieve accounts."

                });

        }

    }
);



/*
========================================================
GET OTP / AUTHENTICATED WS URL
========================================================
*/

app.post(
    "/api/account/:accountId/ws",

    async (req, res) => {

        try {

            if (
                !req.session.deriv
            ) {

                return res
                    .status(401)
                    .json({

                        error:
                            "NOT_LOGGED_IN"

                    });

            }



            const accountId =
                req.params.accountId;



            const response =
                await fetch(

                    DERIV_API +
                    "/trading/v1/options/accounts/" +
                    encodeURIComponent(
                        accountId
                    ) +
                    "/otp",

                    {

                        method:
                            "POST",

                        headers: {

                            "Deriv-App-ID":
                                CLIENT_ID,

                            "Authorization":
                                "Bearer " +
                                req.session.deriv
                                    .accessToken,

                            "Content-Type":
                                "application/json"

                        }

                    }

                );



            const data =
                await response.json();



            if (!response.ok) {

                console.error(
                    "OTP ERROR:",
                    data
                );

                return res
                    .status(
                        response.status
                    )
                    .json(data);

            }



            /*
            Return only the ready-to-use
            WebSocket URL.

            The OAuth access token itself
            remains on the server.
            */

            res.json({

                websocket_url:
                    data.websocket_url ||
                    data.url ||
                    null

            });

        }

        catch (error) {

            console.error(
                error
            );

            res
                .status(500)
                .json({

                    error:
                        "Could not create authenticated WebSocket."

                });

        }

    }
);



/*
========================================================
HEALTH CHECK
========================================================
*/

app.get(
    "/api/health",

    (req, res) => {

        res.json({

            server:
                "online",

            derivConfigured:
                Boolean(
                    CLIENT_ID
                ),

            authenticated:
                Boolean(
                    req.session.deriv
                )

        });

    }
);



/*
========================================================
START SERVER
========================================================
*/

app.listen(
    PORT,
    "0.0.0.0",

    () => {

        console.log(
            ""
        );

        console.log(
            "======================================"
        );

        console.log(
            " DERIV MARKET ANALYZER V3"
        );

        console.log(
            "======================================"
        );

        console.log(
            "Server running on:"
        );

        console.log(
            "http://localhost:" +
            PORT
        );

        console.log(
            "======================================"
        );

    }
);