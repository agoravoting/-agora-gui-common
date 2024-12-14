/**
 * This file is part of common-ui.
 * Copyright (C) 2015-2016  Sequent Tech Inc <legal@sequentech.io>

 * common-ui is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * common-ui  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with common-ui.  If not, see <http://www.gnu.org/licenses/>.
**/

angular.module('avRegistration')
  .directive(
    'avLogin',
    function(
      Authmethod,
      StateDataService,
      $state,
      $location,
      $cookies,
      $window,
      $timeout,
      ConfigService,
      Patterns)
    {
      var OIDC_CSRF_COOKIE = "OIDC_CSRF";
      var OIDC_ERROR_COOKIE = "OIDC_ERROR_COOKIE";
      // we use it as something similar to a controller here
      function link(scope, element, attrs)
      {
        scope.isCensusQuery = attrs.isCensusQuery;
        scope.isQuery = "true" === $location.search()['query'];
        scope.withCode = attrs.withCode;
        scope.username = attrs.username;
        scope.isOtl = attrs.isOtl;
        scope.isOpenId = attrs.isOpenId;
        scope.otlSecret = attrs.otlSecret;
        scope.error = null;
        scope.errorData = null;
        scope.current_alt_auth_method_id = undefined;
        scope.alternative_auth_methods = null;

        scope.csrf = null;

        if (!attrs.withAltMethod || !attrs.selectedAltMethod) {
          scope.selectedAltMethod = null;
        } else {
          scope.selectedAltMethod = attrs.selectedAltMethod;
        }

        // by default
        scope.hide_default_login_lookup_field = false;
        var adminId = ConfigService.freeAuthId + '';
        var autheventid = null;

        function parseOidcErrorCookie()
        {
          if (!$cookies.get(OIDC_ERROR_COOKIE))
          {
            return null;
          }
          var oidcError = angular.fromJson($cookies.get(OIDC_ERROR_COOKIE));
          $cookies.remove(OIDC_ERROR_COOKIE);

          // validate csrf token format and data
          return oidcError;
        }

        scope.oidcError = parseOidcErrorCookie();
        if (scope.oidcError) {
          scope.selectedAltMethod = scope.oidcError.altAuthMethodId;
          /* jshint ignore:start */
          setError(
            scope.oidcError.errorCodename,
            'avRegistration.loginError.openid-connect.' + scope.oidcError.errorCodename
          );
          /* jshint ignore:end */
        }

        // simply redirect to login
        function simpleRedirectToLogin()
        {
          if (scope.csrf)
          {
            $window.location.href = "/election/" + scope.csrf.eventId + "/public/login";
          } else  {
            $window.location.href = ConfigService.defaultRoute;
          }
        }

        // Gets the list of current auth method providers
        function getCurrentOidcProviders(auth_event)
        {
          if (
            !auth_event.auth_method_config ||
            !auth_event.auth_method_config.config ||
            !auth_event.auth_method_config.config.provider_ids
          ) {
            return [];
          }
          return _.map(
            auth_event.auth_method_config.config.provider_ids,
            function (provider_id) {
              return _.find(
                auth_event.oidc_providers,
                function (provider) { return provider.public_info.id === provider_id; }
              );
            }
          );
        }

        // Returns the logout url if any from the appropiate openidprovider
        // TODO: logout asumes that you are using the first provider, so it
        // basically supports only one provider
        function getLogoutUri(authEvent)
        {
          var eventId = null;
          var redirectUri = null;
          if (scope.csrf)
          {
            eventId = scope.csrf.eventId;
            redirectUri = "/election/" + eventId + "/public/login";
          } else {
            redirectUri = ConfigService.defaultRoute;
          }
          scope.oidc_providers = authEvent.oidc_providers;
          scope.current_oidc_providers = getCurrentOidcProviders(authEvent);

          if (scope.current_oidc_providers.length === 0)
          {
            return redirectUri;
          }

          var oidcProvider = _.find(
            authEvent.oidc_providers,
            function (provider) {
              return provider.public_info.id === scope.csrf.providerId;
            }
          );

          if (!oidcProvider || !oidcProvider.logout_uri) {
            return redirectUri;
          }

          redirectUri = oidcProvider.logout_uri;
          redirectUri = redirectUri.replace("__EVENT_ID__", "" + eventId);

          var postfix = "_authevent_" + eventId;
          if (!!$cookies.get("id_token_" + postfix))
          {
            redirectUri = redirectUri.replace(
              "__ID_TOKEN__", $cookies.get("id_token_" + postfix)
            );

          // if __ID_TOKEN__ is there but we cannot replace it, we need to
          // directly redirect to the login, otherwise the URI might show an
          // error 500
          } else if (redirectUri.indexOf("__ID_TOKEN__") > -1)
          {
            redirectUri = "/election/" + eventId + "/public/login";
          }

          return redirectUri;
        }

        // Redirects to the login page of the respective event_id if any
        function redirectToLogin()
        {
          if (scope.sendingData)
          {
            return;
          }

          scope.sendingData = true;

          if (!scope.csrf || !scope.csrf.eventId)
          {
            $window.location.href = ConfigService.defaultRoute;
            return;
          }

          var eventId = scope.csrf.eventId;
          Authmethod.viewEvent(eventId)
            .then(
              function onSuccess(response)
              {
                if (
                  response.data.status !== "ok" ||
                  !response.data.events
                ) {
                  simpleRedirectToLogin();
                  return;
                }

                var postfix = "_authevent_" + eventId;
                var uri = getLogoutUri(response.data.events);
                $cookies.remove("id_token_" + postfix);
                $window.location.href = uri;
              },
              function onError()
              {
                simpleRedirectToLogin();
              }
            );
        }

        // Get the decoded value of a uri parameter from any uri. The uri does
        // not need to have any domain, it can start with the character "?"
        function getURIParameter(paramName, uri)
        {
          var paramName2 = paramName.replace(/[\[\]]/g, '\\$&');
          var rx = new RegExp('[?&]' + paramName2 + '(=([^&#]*)|&|#|$)');
          var params = rx.exec(uri);

          if (!params)
          {
            return null;
          }

          if (!params[2])
          {
            return '';
          }
          return decodeURIComponent(params[2].replace(/\+/g, ' '));
        }

        function setOIDCErrorCookie(errorCodename)
        {
          var options = {};
          if (ConfigService.authTokenExpirationSeconds) {
            options.expires = new Date(
              Date.now() + 1000 * ConfigService.authTokenExpirationSeconds
            );
          }
          $cookies.put(
            OIDC_ERROR_COOKIE,
            angular.toJson({
              altAuthMethodId: scope.current_alt_auth_method_id,
              eventId: scope.eventId,
              errorCodename: errorCodename
            }),
            options
          );
        }

        function setError(errorCodename, error)
        {
          scope.error = error;
          scope.errorData = angular.toJson({
            support: ConfigService.contact.email
          });
          if (scope.isOpenId) {
            setOIDCErrorCookie(errorCodename);
            redirectToLogin();
          }
        }

        // Validates the CSRF token
        function validateCsrfToken()
        {
          if (!$cookies.get(OIDC_CSRF_COOKIE))
          {
            setOIDCErrorCookie("unexpectedOIDCRedirect");
            redirectToLogin();
            return null;
          }

          // validate csrf token format and data
          var csrf = scope.csrf = angular.fromJson($cookies.get(OIDC_CSRF_COOKIE));
          var uri = $window.location.search;

          // NOTE: if you need to debug this callback, obtain the callback
          // URL, get the callback received in the server (to obtain the
          // nonce) that was received by the client and change the data here
          // accordingly and set here the debug break point, then execute
          // a line like the following in the comment.
          //
          // The only data that needs to be changed is the randomNonnce and
          // the eventId.
          //
          // csrf = scope.csrf = {
          //   randomNonce: 'something',
          //   randomState: getURIParameter("state", uri),
          //   altAuthMethodId: null,
          //   created: Date.now(),
          //   providerId: 'google',
          //   eventId: 11111
          // };

          $cookies.remove(OIDC_CSRF_COOKIE);
          var isCsrfValid = (!!csrf &&
            angular.isObject(csrf) &&
            angular.isString(csrf.randomState) &&
            angular.isString(csrf.randomNonce) &&
            angular.isString(csrf.providerId) &&
            angular.isNumber(csrf.created) &&
            angular.isDefined(csrf.altAuthMethodId) &&
            getURIParameter("state", uri) === csrf.randomState &&
            csrf.created - Date.now() < ConfigService.authTokenExpirationSeconds
          );

          if (!isCsrfValid)
          {
            setOIDCErrorCookie("invalidCsrf");
            redirectToLogin();
            return null;
          }
          return true;
        }

        if (scope.isOpenId)
        {
          if (!validateCsrfToken()) {
            return;
          }
          autheventid = scope.eventId = attrs.eventId = scope.csrf.eventId;
          scope.selectedAltMethod = scope.csrf.altAuthMethodId;
          scope.setLoginOIDC = true;
        } else {
          autheventid = scope.eventId = attrs.eventId;
        }
        scope.orgName = ConfigService.organization.orgName;

        // redirect from admin login to admin elections if login is not needed
        var autheventCookie = $cookies.get('authevent_' + adminId);
        var authCookie = $cookies.get('auth_authevent_' + adminId);
        if (!!autheventCookie && autheventCookie === adminId &&
          autheventid === adminId && !!authCookie)
        {
          $window.location.href = '/admin/elections';
        }
        scope.sendingData = false;

        scope.currentFormStep = 0;

        scope.stateData = StateDataService.getData();
        scope.successfulRegistration = scope.stateData.successfulRegistration || false;

        scope.signupLink = ConfigService.signupLink;

        scope.allowUserResend = false;
        scope.censusQuery = "not-sent";

        scope.code = null;
        if (attrs.code && attrs.code.length > 0) {
          scope.code = attrs.code;
        }
        scope.email = null;
        if (attrs.email && attrs.email.length > 0) {
          scope.email = attrs.email;
        }

        scope.isAdmin = false;
        if (autheventid === adminId) {
          scope.isAdmin = true;
        }

        function isValidTel(inputName) {
          if (!document.getElementById(inputName)) {
            return false;
          }
          var telInput = angular.element(document.getElementById(inputName));
          return telInput.intlTelInput("isValidNumber");
        }

        function isValidEmail(email) {
          var pattern = Patterns.get('email');
          return null !== email.match(pattern);
        }

        // obtain the openid login data
        function getOpenidLoginData()
        {
          var uri = $window.location.search;

          // Auth data to send back to our backend
          var data = {
            code: getURIParameter("code", uri),
            provider_id: scope.csrf.providerId,
            nonce: scope.csrf.randomNonce
          };

          var options = {};
          if (ConfigService.authTokenExpirationSeconds) {
            options.expires = new Date(
              Date.now() + 1000 * ConfigService.authTokenExpirationSeconds
            );
          }

          var postfix = "_authevent_" + scope.csrf.eventId;
          $cookies.put("code_" + postfix, data.code, options);

          return data;
        }

        /**
         * Send auth codes now to the voter
         */
        scope.resendAuthCode = function(field) {
          // if invalid method or already sending data, do not proceed
          if (
            scope.sendingData || 
            !(
              scope.hasOtpFieldsCode ||
              _.contains(["email", "email-otp", "sms", "sms-otp"], scope.method)
            )
          ) {
              return;
          }

          // if telIndex or emailIndex not set when needed, do not proceed
          if (
            !scope.hasOtpFieldsCode &&
            (
              (
                _.contains(["sms", "sms-otp"], scope.method) &&
                scope.telIndex === -1 &&
                !scope.hide_default_login_lookup_field
              ) || 
              (
                _.contains(["email", "email-otp"], scope.method) &&
                scope.emailIndex === -1 &&
                !scope.hide_default_login_lookup_field
              )
            )
          ) {
            return;
          }

          // obtain the data to be sent to the iam to request
          // new auth codes by filtering and validating login fields 
          // with steps == undefined or included in step 0
          var stop = false;
          var data = _.object(
            _.filter(
              scope.login_fields, 
              function (element, index) {
                element.index = index;
                return (
                  element.steps === undefined || 
                  element.steps.indexOf(0) !== -1
                );
              }
            ).map(
              function (element) {
                if (
                  (
                    _.contains(["sms", "sms-otp"], scope.method) &&
                    element.index === scope.telIndex &&
                    !isValidTel("input" + scope.telIndex)
                  ) || (
                    _.contains(["email", "email-otp"], scope.method) &&
                    element.index === scope.emailIndex &&
                    !isValidEmail(element.value)
                  )
                ) {
                  stop = true;
                }
                return [element.name, element.value];
              }
            )
          );
          
          // if any issue found, do not proceed
          if (stop) {
            return;
          }

          // set alternative auth method id
          if (scope.current_alt_auth_method_id) {
            data.alt_auth_method_id = scope.current_alt_auth_method_id;
          }

          // reset code field, as we are going to send a new one
          if (!!field) {
            field.value = "";
          }

          function onAuthCodeSent(response) {
            // disabling login that are from previous step
            _.each(
              scope.login_fields, 
              function (element) {
                if (
                  element.steps === undefined || 
                  element.steps.indexOf(0) !== -1
                ) {
                  element.disabled = true;
                }
              }
            );
            scope.currentFormStep = 1;
            setError(null, null);
            $timeout(scope.sendingDataTimeout, 3000);
          }

          scope.sendingData = true;
          if (scope.skipSendAuthCode) {
            onAuthCodeSent();
            scope.skipSendAuthCode = false;
            return;
          }

          Authmethod.resendAuthCode(data, autheventid)
            .then(
              onAuthCodeSent,
              function onError(response) {
                $timeout(scope.sendingDataTimeout, 3000);
                setError(
                  null,
                  'avRegistration.errorSendingAuthCode'
                );
              }
            );
        };

        scope.sendingDataTimeout = function () {
          scope.sendingData = false;
        };

        scope.parseAuthToken = function () {
          if (scope.method !== 'smart-link' || scope.withCode) {
            return;
          }
          scope.authToken = $location.search()['auth-token'];
          if (scope.authToken === undefined) {
            return;
          }

          var length = 'khmac:///'.length;
          var tails = scope.authToken.substr(length);
          var message = tails.split('/')[1];
          scope.user_id = message.split(':')[0];
        };

        scope.checkCensus = function(valid) {
          if (!valid) {
            return;
          }

          if (scope.sendingData) {
            return;
          }
          scope.censusQuery = "querying";

          var data = {
            'captcha_code': Authmethod.captcha_code,
          };
          _.each(scope.login_fields, function (field) {
            data[field.name] = field.value;
          });

          scope.sendingData = true;
          Authmethod.censusQuery(data, autheventid)
            .then(
              function onSuccess(response) {
                scope.sendingData = false;
                scope.censusQueryData = response.data;
                scope.censusQuery = "success";
              },
              function onError(response) {
                scope.sendingData = false;
                scope.censusQuery = "fail";
              }
            );
        };

        scope.otlAuth = function(valid) {
          if (!valid) {
            return;
          }

          if (scope.sendingData) {
            return;
          }
          scope.otlStatus = "querying";

          var data = {
            'captcha_code': Authmethod.captcha_code,
            '__otl_secret': scope.otlSecret
          };
          _.each(scope.login_fields, function (field) {
            data[field.name] = field.value;
          });

          scope.sendingData = true;
          Authmethod.authenticateOtl(data, autheventid)
            .then(
              function onSuccess(response) {
                scope.sendingData = false;
                scope.otpCode = response.data.code;
                scope.otlResponseData = response.data;
                scope.otlStatus = "success";
              },
              function onError(_response) {
                scope.sendingData = false;
                scope.otpCode = undefined;
                scope.otlResponseData = {};
                scope.otlStatus = "fail";
              }
            );
        };

        scope.loginUser = function(valid) {
          if (!valid) {
            return;
          }
          if (scope.sendingData) {
            return;
          }

          // loginUser
          var data = {};
          if (scope.isOpenId) {
            data = getOpenidLoginData();
          } else {
            if (
              !scope.withCode &&
              (
                scope.hasOtpFieldsCode ||
                _.contains(['sms-otp', 'email-otp'], scope.method)
              ) &&
              scope.currentFormStep === 0
            ) {
              scope.resendAuthCode();
              return;
            }
            data['captcha_code'] = Authmethod.captcha_code;

            var hasEmptyCode = false;
            _.each(scope.login_fields, function (field) {
              if (angular.isUndefined(field.value)) {
                data[field.name] = '';
              }
              if (field.type === 'email') {
                scope.email = field.value;
              } else if (_.contains(['code', 'otp-code'], field.type)) {
                if (!angular.isString(field.value)) {
                  // This will stop the login process
                  hasEmptyCode = true;
                }
                field.value = field.value.trim().replace(/ |\n|\t|-|_/g,'').toUpperCase();
              }
              data[field.name] = field.value;
            });

            // This happens in non sms-otp or email-otp that have a code/otp-code
            // field empty
            if (hasEmptyCode) {
              return;
            }

            // Get the smart link authentication token and set it in the data if
            // this is an auth event with smart-link auth method
            if (scope.method === 'smart-link' && !scope.withCode)
            {
              data['auth-token'] = $location.search()['auth-token'];
            }
          }

          // set alternative auth method id
          if (scope.current_alt_auth_method_id) {
            data.alt_auth_method_id = scope.current_alt_auth_method_id;
          }

          scope.sendingData = true;
          setError(null, null);

          var sessionStartedAtMs = Date.now();
          Authmethod
            .login(data, autheventid)
            .then(
              function onSuccess(response) {
                if (response.data.status === "ok") {
                  var postfix = "_authevent_" + autheventid;
                  var options = {};
                  var authToken = response.data['auth-token'];
                  var decodedToken = Authmethod.decodeToken(authToken);
                  options.expires = new Date(
                    sessionStartedAtMs + 1000 * decodedToken.expiry_secs_diff
                  );
                  $cookies.put("authevent_" + autheventid, autheventid, options);
                  $cookies.put("userid" + postfix, response.data.username, options);
                  $cookies.put("user" + postfix, scope.email || response.data.username || response.data.email, options);
                  $cookies.put("auth" + postfix, authToken, options);
                  $cookies.put("isAdmin" + postfix, scope.isAdmin, options);
                  Authmethod.setAuth(authToken, scope.isAdmin, autheventid);
                  var votingScreenPath = (scope.isQuery || (scope.base_authevent && scope.base_authevent.force_census_query)) ? '/eligibility' : '/vote';
                  if (scope.isAdmin)
                  {
                    Authmethod.getUserInfo()
                      .then(
                        function onSuccess(response) {
                          var redirectUrl = $window.sessionStorage.getItem("redirect");
                          if (redirectUrl) {
                            $window.sessionStorage.removeItem("redirect");
                          } else {
                            redirectUrl = '/admin/elections';
                          }
                          $cookies.put("user" + postfix, response.data.email || scope.email || response.data.username, options);
                          $window.location.href = redirectUrl;
                        },
                        function onError(response) {
                          $window.location.href = '/admin/elections';
                        }
                      );
                  }
                  else if (angular.isDefined(response.data['redirect-to-url']))
                  {
                    $window.location.href = response.data['redirect-to-url'];
                  }
                  // if it's an election with no children elections
                  else if (angular.isDefined(response.data['vote-permission-token']))
                  {
                    var accessToken = response.data['vote-permission-token'];
                    var decodedAccessToken = Authmethod.decodeToken(accessToken);
                    $window.sessionStorage.setItem(
                      "vote_permission_tokens", 
                      JSON.stringify([{
                        electionId: autheventid,
                        token: response.data['vote-permission-token'],
                        isFirst: true,
                        sessionStartedAtMs: sessionStartedAtMs,
                        sessionEndsAtMs: sessionStartedAtMs + 1000 * decodedAccessToken.expiry_secs_diff
                      }])
                    );
                    $window.sessionStorage.setItem(
                      "show-pdf",
                      !!response.data['show-pdf']
                    );
                    $window.location.href = '/booth/' + autheventid + votingScreenPath;
                  }
                  // if it's an election with children elections then show access to them
                  else if (angular.isDefined(response.data['vote-children-info']))
                  {
                    // assumes the iam response has the same children
                    var tokens = _
                      .chain(response.data['vote-children-info'])
                      .map(function (child, index) {
                        var accessToken = child['vote-permission-token'];
                        var decodedAccessToken = accessToken && Authmethod.decodeToken(accessToken) || null;
                        return {
                          electionId: child['auth-event-id'],
                          token: child['vote-permission-token'] || null,
                          skipped: false,
                          voted: false,
                          numSuccessfulLoginsAllowed: child['num-successful-logins-allowed'],
                          numSuccessfulLogins: child['num-successful-logins'],
                          isFirst: index === 0,
                          sessionStartedAtMs: sessionStartedAtMs,
                          sessionEndsAtMs: sessionStartedAtMs + 1000 * (decodedAccessToken && decodedAccessToken.expiry_secs_diff || null)
                        };
                      })
                      .value();
                    $window.sessionStorage.setItem(
                      "vote_permission_tokens", 
                      JSON.stringify(tokens)
                    );

                    $window.location.href = '/booth/' + autheventid + votingScreenPath;
                  } else {
                    setError(
                      "unrecognizedServerResponse",
                      'avRegistration.loginError.' + scope.method + '.unrecognizedServerResponse'
                    );
                  }
                } else {
                  scope.sendingData = false;
                  setError(
                    "invalidServerResponse",
                    'avRegistration.loginError.' + scope.method + '.invalidServerResponse'
                  );
                }
            },
            function onError(response) {
              scope.sendingData = false;
              var codename = response.data.error_codename;

              setError(
                codename,
                'avRegistration.loginError.' + scope.method + '.' + codename
              );
            }
          );
        };

        scope.getUriParam = function (paramName) {
          var uri = $window.location.href;
          var paramName2 = paramName
            .replace(/[\[\]]/g, '\\$&')
            .replace(/ /g, '%20');
          var rx = new RegExp('[?&]' + paramName2 + '(=([^&#]*)|&|#|$)');
          var params = rx.exec(uri);

          if (!params)
          {
              return null;
          }

          if (!params[2])
          {
              return '';
          }
          return decodeURIComponent(params[2].replace(/\+/g, ' ')) || undefined;
        };

        /**
         * Returns the translated name of the given alternative authentication
         * method.
         * @param {*} altAuthMethod altAuthMethod object
         */
        scope.getAltAuthMethodName = function(altAuthMethod) {
          var langCode = $window.i18next.resolvedLanguage;
          if (
            altAuthMethod.public_name_i18n &&
            altAuthMethod.public_name_i18n[langCode]
          ) {
            return altAuthMethod.public_name_i18n[langCode];
          } else {
            return altAuthMethod.public_name;
          }
        };

        /**
         * Sets the current alt auth method
         * @param {*} altAuthMethod altAuthMethod object
         */
        scope.setCurrentAltAuthMethod = function(altAuthMethod, isClick) {
          var authevent = angular.copy(scope.base_authevent);
          if (altAuthMethod === null) {
            scope.current_alt_auth_method_id = null;
            // isOpenId connect is only automatically set in the redirect view
            // so we need to set it here
            scope.isOpenId = (
              scope.isOpenId || authevent.auth_method === 'openid-connect'
            );
            scope.apply(authevent);
            return;
          }
          if (altAuthMethod.id === scope.current_alt_auth_method_id) {
            return;
          }

          // smart link cannot be enabled if it doesn't come from the url
          if (
            !!isClick &&
            scope.selectedAltMethod !== 'smart-link' &&
            altAuthMethod.auth_method_name === 'smart-link'
          ) {
            return;
          }

          scope.isOpenId = altAuthMethod.auth_method === 'openid-connect';
          scope.current_alt_auth_method_id = altAuthMethod.id;
          authevent.extra_fields = altAuthMethod.extra_fields;
          authevent.auth_method_config = altAuthMethod.auth_method_config;
          authevent.auth_method = altAuthMethod.auth_method_name;
          scope.apply(authevent);
        };

        scope.apply = function(authevent) {
            scope.hasOtpFieldsCode = Authmethod.hasOtpCodeField(authevent);
            scope.method = authevent['auth_method'];
            scope.oidc_providers = authevent.oidc_providers;
            scope.current_oidc_providers = getCurrentOidcProviders(authevent);

            if (scope.hasOtpFieldsCode ||
              _.contains(['sms-otp', 'email-otp'], scope.method)) {
                scope.skipSendAuthCode = scope.successfulRegistration;
            }

            scope.name = authevent['name'];
            scope.parseAuthToken();
            scope.registrationAllowed = (
              (authevent['census'] === 'open') &&
              (autheventid !== adminId || ConfigService.allowAdminRegistration)
            );

            if (!scope.isCensusQuery && !scope.withCode && !scope.isOtl) {
              scope.login_fields = Authmethod.getLoginFields(authevent);
            } else if (scope.withCode) {
              scope.login_fields = Authmethod.getLoginWithCode(authevent);
            } else if (scope.isCensusQuery) {
              scope.login_fields = Authmethod.getCensusQueryFields(authevent);
            } else if (scope.isOtl) {
              scope.login_fields = Authmethod.getOtlFields(authevent);
            }

            // show some fields first
            scope.login_fields.sort(function (a, b) {
              var initialFields = [
                "tlf", "email", "code", "otp-code"
              ];
              if (initialFields.includes(a.type) && !initialFields.includes(b.type)) {
                return -1;
              }
              if (!initialFields.includes(a.type) && initialFields.includes(b.type)) {
                return 1;
              }
              return 0;
            });
            scope.hide_default_login_lookup_field = authevent.hide_default_login_lookup_field;
            scope.telIndex = -1;
            scope.emailIndex = -1;
            scope.telField = null;
            scope.allowUserResend = (function () {
              if (scope.withCode) {
                return false;
              }
              var ret = false;
              var href = $location.path();
              var adminMatch = href.match(/^\/admin\//);
              var electionsMatch = href.match(/^\/(elections|election)\/([0-9]+)\//);

              if (_.isArray(adminMatch)) {
                ret = true;
              } else if (_.isArray(electionsMatch) && 3 === electionsMatch.length) {
                ret = (_.isObject(authevent.auth_method_config) &&
                       _.isObject(authevent.auth_method_config.config) &&
                       true === authevent.auth_method_config.config.allow_user_resend);
              }
              return ret;
            })();

            var fields = _.map(
              scope.login_fields,
              function (el, index) {
                if (!!scope.stateData[el.name]) {
                  el.value = scope.stateData[el.name];
                  el.disabled = true;
                } else {
                  var uriValue = scope.getUriParam(el.name);
                  if (angular.isString(uriValue)) {
                    el.value = uriValue;
                    el.disabled = true;
                  } else {
                    el.value = null;
                    el.disabled = false;
                  }
                }
                if (el.type === "email") {
                  if (scope.email !== null) {
                    el.value = scope.email;
                    el.disabled = true;
                    if (scope.method === "email-otp") {
                      scope.currentFormStep = 1;
                    }
                  }
                  scope.emailIndex = index;
                } else if (el.type === "code" && scope.code !== null) {
                  el.value = scope.code.trim().replace(/ |\n|\t|-|_/g,'').toUpperCase();
                  el.disabled = true;
                } else if (el.type === "tlf" && scope.method === "sms") {
                  if (scope.email !== null && scope.email.indexOf('@') === -1) {
                    el.value = scope.email;
                    el.disabled = true;
                  }
                  scope.telIndex = index+1;
                  scope.telField = el;
                } else if (el.type === "tlf" && scope.method === "sms-otp") {
                  if (scope.email !== null && scope.email.indexOf('@') === -1) {
                    el.value = scope.email;
                    el.disabled = true;
                    scope.currentFormStep = 1;
                  }
                  scope.telIndex = index+1;
                  scope.telField = el;
                } else if (el.name === '__username' && scope.withCode) {
                  el.value = scope.username;
                  el.disabled = true;
                } else if (
                  el.name === 'user_id' &&
                  scope.method === 'smart-link'
                ) {
                  el.value = scope.user_id;
                  el.disabled = true;
                }
                return el;
              });

            // if all the login fields required on authentication that are not
            // of type code have been filled and we are in email-otp or sms-otp,
            // we should enable jump to currantFormStep = 1. Normally this 
            // already happened, but it could be that it didn't if the main
            // extra_field is hidden
            if (
              scope.currentFormStep === 0 && 
              _.contains(['email-otp', 'sms-otp'], scope.auth_method)
            ) {
              var unfilledFields = _.filter(
                fields,
                function (el) {
                  return (
                    el.value === null &&
                    !_.contains(['otp-code', 'code'], el.type)
                  );
                }
              );
              if (unfilledFields.length === 0) {
                scope.currentFormStep = 1;
              }
            }

            // if not all the fields all filled at this point, then we stop
            // here. otp-code fields do not count, because loginUser
            // function will send the appropiate OTP code if required
            var filledFields = _.filter(
              fields,
              function (el) {
                return (
                  el.value !== null ||
                  el.type === 'otp-code'
                );
              }
            );
            if (
              !scope.isOpenId &&
              filledFields.length !== scope.login_fields.length
            ) {
              return;
            }

            // if all fields all filled in and it's not OpenID Connect do
            // auto-login
            if (
              !scope.isOpenId && (authevent.auth_method === 'openid-connect') &&
              !scope.isOtl &&
              !scope.isCensusQuery &&
              !scope.withCode &&
              !scope.oidcError
            ) {
              scope.loginUser(true);
            }
            if (scope.setLoginOIDC) {
              scope.loginUser(true);
            }
        };

        scope.view = function(id) {
            Authmethod.viewEvent(id)
                .then(
                  function onSuccess(response) {
                    if (response.data.status === "ok") {
                      scope.base_authevent = angular.copy(response.data.events);
                      scope.alternative_auth_methods = scope.base_authevent.alternative_auth_methods;
                      var altAuthMethod = _.find(
                        scope.alternative_auth_methods,
                        function (altAuthMethod) {
                          return altAuthMethod.id === scope.selectedAltMethod; 
                        }
                      ) || null;
                      scope.setCurrentAltAuthMethod(altAuthMethod);
                    } else {
                        document.querySelector(".input-error").style.display = "block";
                    }
                  },
                  function onError(response) {
                    document.querySelector(".input-error").style.display = "block";
                  }
                );
        };
        scope.view(autheventid);

        scope.goSignup = function() {
            $state.go('registration.register', {id: autheventid});
        };

        scope.forgotPassword = function() {
            console.log('forgotPassword');
        };

        // generate a cryptogrpahically secure random string
        function randomStr()
        {
            /* jshint ignore:start */
            var random = sjcl.random.randomWords(/* bitlength */ 2048 / 32, 0);
            return sjcl.codec.hex.fromBits(random);
            /* jshint ignore:end */
        }

        // OpenIDConnect sets a cookie that is used to create a CSRF token
        // similar to what is mentioned here:
        // https://developers.google.com/identity/protocols/OpenIDConnect#createxsrftoken
        scope.openidConnectAuth = function(provider)
        {
          // find provider
          if (!provider)
          {
            setError(
              'providerNotFound',
              'avRegistration.loginError.openid-connect.providerNotFound'
            );
            return;
          }

          var randomState = randomStr();
          var randomNonce = randomStr();
          var options = {};
          if (ConfigService.authTokenExpirationSeconds) {
            options.expires = new Date(
              Date.now() + 1000 * ConfigService.authTokenExpirationSeconds
            );
          }
          $cookies.put(
            OIDC_CSRF_COOKIE,
            angular.toJson({
              randomState: randomState,
              randomNonce: randomNonce,
              altAuthMethodId: scope.current_alt_auth_method_id,
              created: Date.now(),
              eventId: scope.eventId,
              providerId: provider.public_info.id
            }),
            options
          );

          // Craft the OpenID Connect auth URI
          var authURI = (provider.public_info.authorization_endpoint +
            "?response_type=code" +
            "&client_id=" + encodeURIComponent(provider.public_info.client_id) +
            "&scope=" + encodeURIComponent(provider.public_info.scope) +
            "&redirect_uri=" + encodeURIComponent(
              $window.location.origin +
              "/election/login-openid-connect-redirect"
            ) +
            "&state=" + randomState +
            "&nonce=" + randomNonce
          );

          // Redirect to the Auth URI
          $window.location.href = authURI;
        };
    }
    return {
      restrict: 'AE',
      scope: true,
      link: link,
      templateUrl: 'avRegistration/login-directive/login-directive.html'
    };
  });
