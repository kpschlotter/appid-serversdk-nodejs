/*
 Copyright 2017 IBM Corp.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

const express = require("express");
const session = require("express-session");
const log4js = require("log4js");
const passport = require("passport")
const flash = require("connect-flash");
const path = require('path');

const helmet = require("helmet");
const bodyParser = require("body-parser"); // get information from html forms
const cookieParser = require("cookie-parser");
const WebAppStrategy = require("./../lib/appid-sdk").WebAppStrategy;

const app = express();
const logger = log4js.getLogger("testApp");

// Below URLs will be used for App ID OAuth flows
const LANDING_PAGE_URL = "/web-app-sample.html";
const LOGIN_URL = "/ibm/bluemix/appid/login";
const SIGN_UP_URL = "/ibm/bluemix/appid/sign_up";
const CHANGE_PASSWORD_URL = "/ibm/bluemix/appid/change_password";
const CHANGE_DETAILS_URL = "/ibm/bluemix/appid/change_details";
const FORGOT_PASSWORD_URL = "/ibm/bluemix/appid/forgot_password";
const LOGIN_ANON_URL = "/ibm/bluemix/appid/loginanon";
const CALLBACK_URL = "/ibm/cloud/appid/callback";
const LOGOUT_URL = "/ibm/bluemix/appid/logout";
const ROP_LOGIN_PAGE_URL = "/ibm/bluemix/appid/rop/login";

app.use(helmet());
app.use(flash());
app.use(cookieParser());
app.set('views', path.join(__dirname, './views'));
app.set('view engine', 'ejs'); // set up ejs for templating

// Setup express application to use express-session middleware
// Must be configured with proper session storage for production
// environments. See https://github.com/expressjs/session for
// additional documentation
app.use(session({
	secret: "123456",
	resave: true,
	saveUninitialized: true
}));

// Use static resources from /samples directory
app.use(express.static(__dirname));

// Configure express application to use passportjs
app.use(passport.initialize());
app.use(passport.session());

// Configure passportjs to use WebAppStrategy
let webAppStrategy = new WebAppStrategy({
	tenantId: "73169514-a680-401f-84cd-f6c00b47573d",
  clientId: "e67aef9e-1e55-465d-a3ba-6fa92a4bd60a",
  secret: "MTZkYTBkZDYtZjU3MS00MmQwLWEzYWItZjkzYWIwNzcwMzQ2",
  oauthServerUrl: "https://eu-de.appid.cloud.ibm.com/oauth/v4/73169514-a680-401f-84cd-f6c00b47573d",
	redirectUri: "http://localhost:3000" + CALLBACK_URL
});
passport.use(webAppStrategy);

// Configure passportjs with user serialization/deserialization. This is required
// for authenticated session persistence accross HTTP requests. See passportjs docs
// for additional information http://passportjs.org/docs
passport.serializeUser(function(user, cb) {
	cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
	cb(null, obj);
});

// Explicit login endpoint. Will always redirect browser to login widget due to {forceLogin: true}.
// If forceLogin is set to false redirect to login widget will not occur of already authenticated users.
// app.get(LOGIN_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
// 	successRedirect: LANDING_PAGE_URL,
// 	forceLogin: true
// }), (req, res) => {
// 	logger.info("LOGIN CALLBACK", req.user.name);
// });
// auth with IBM appid
app.get(LOGIN_URL, (req, res, next) => {
  // call passport authentication passing the "local" strategy name and a callback function
  passport.authenticate('appid-webapp-strategy', (error, user, info) => {
    // this will execute in any case, even if a passport strategy will find an error
    // log everything to console
    logger.info("AUTHCALLBACK err",error);
    logger.info("AUTHCALLBACK user",user);
    logger.info("AUTHCALLBACK info", info);

    if (error) {
      res.status(401).send(error);
    } else if (!user) {
      res.status(401).send(info);
    } else {
      req.logIn(user, err => {
				if (err) {
					return next(err);
				}
				return res.redirect(LANDING_PAGE_URL);
			});
    }
    res.status(401).send(info);
  })(req, res, next);
});

// Explicit forgot password endpoint. Will always redirect browser to forgot password widget screen.
app.get(FORGOT_PASSWORD_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
	successRedirect: LANDING_PAGE_URL,
	show: WebAppStrategy.FORGOT_PASSWORD
}));

// Explicit change details endpoint. Will always redirect browser to change details widget screen.
app.get(CHANGE_DETAILS_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
	successRedirect: LANDING_PAGE_URL,
	show: WebAppStrategy.CHANGE_DETAILS
}));

// Explicit change password endpoint. Will always redirect browser to change password widget screen.
app.get(CHANGE_PASSWORD_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
	successRedirect: LANDING_PAGE_URL,
	show: WebAppStrategy.CHANGE_PASSWORD
}));

// Explicit sign up endpoint. Will always redirect browser to sign up widget screen.
// default value - false
app.get(SIGN_UP_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
	successRedirect: LANDING_PAGE_URL,
	show: WebAppStrategy.SIGN_UP
}));

// Explicit anonymous login endpoint. Will always redirect browser for anonymous login due to forceLogin: true
app.get(LOGIN_ANON_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
	successRedirect: LANDING_PAGE_URL,
	allowAnonymousLogin: true,
	allowCreateNewAnonymousUser: true
}));

// Callback to finish the authorization process. Will retrieve access and identity tokens/
// from App ID service and redirect to either (in below order)
// 1. the original URL of the request that triggered authentication, as persisted in HTTP session under WebAppStrategy.ORIGINAL_URL key.
// 2. successRedirect as specified in passport.authenticate(name, {successRedirect: "...."}) invocation
// 3. application root ("/")
 app.get(CALLBACK_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME));

// Logout endpoint. Clears authentication information from session
app.get(LOGOUT_URL, function(req, res) {
	WebAppStrategy.logout(req);
	res.redirect(LANDING_PAGE_URL);
});

function storeRefreshTokenInCookie(req, res, next) {
	const refreshToken = req.session[WebAppStrategy.AUTH_CONTEXT].refreshToken;
	if (refreshToken) {
		/* An example of storing user's refresh-token in a cookie with expiration of a month */
		res.cookie("refreshToken", refreshToken, {maxAge: 1000 * 60 * 60 * 24 * 30 /* 30 days */});
	}
	next();
}

function isLoggedIn(req) {
	return req.session[WebAppStrategy.AUTH_CONTEXT];
}

// Protected area. If current user is not authenticated - redirect to the login widget will be returned.
// In case user is authenticated - a page with current user information will be returned.
app.get("/protected", function tryToRefreshTokenIfNotLoggedIn(req, res, next) {
	if (isLoggedIn(req)) {
		logger.info("tryToRefreshTokenIfNotLoggedIn");
		return next();
	}
	logger.info("Not Logged In");
	if (req.cookies.refreshToken) {
	webAppStrategy.refreshTokens(req, req.cookies.refreshToken).then(function() {
		logger.info("back in refreshToken");
		next();
	}).catch (err => {
		logger.info(err);
		res.status(400).json(err);
	});
} else {
	res.status(403).json({message: "not authenticated"});
}
}, passport.authenticate(WebAppStrategy.STRATEGY_NAME), storeRefreshTokenInCookie, function(req, res) {
	logger.info("/protected");
	res.json(req.user);
});

app.post("/rop/login/submit", bodyParser.urlencoded({extended: false}), passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
	successRedirect: LANDING_PAGE_URL,
	failureRedirect: ROP_LOGIN_PAGE_URL,
	failureFlash : true // allow flash messages
}));

app.get(ROP_LOGIN_PAGE_URL, function(req, res) {
	// render the page and pass in any flash data if it exists
	res.render("login.ejs", { message: req.flash('error') });
});

var port = process.env.PORT || 3000;

app.listen(port, function() {
	logger.info("Listening on http://localhost:" + port + "/web-app-sample.html");
});
