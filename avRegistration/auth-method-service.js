/**
 * This file is part of agora-gui-common.
 * Copyright (C) 2015-2016  Agora Voting SL <agora@agoravoting.com>

 * agora-gui-common is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * agora-gui-common  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with agora-gui-common.  If not, see <http://www.gnu.org/licenses/>.
**/

angular.module('avRegistration')

    .factory('Authmethod', function($http, $cookies, ConfigService, $interval, $location) {
        var backendUrl = ConfigService.authAPI;
        var authId = ConfigService.freeAuthId;
        var authmethod = {};
        authmethod.captcha_code = null;
        authmethod.captcha_image_url = "";
        authmethod.captcha_status = "";
        authmethod.admin = false;
        
        authmethod.getAuthevent = function() {
          var adminId = ConfigService.freeAuthId + '';
          var href = $location.path();
          var authevent = '';

          var adminMatch = href.match(/^\/admin\//);
          var boothMatch = href.match(/^\/booth\/([0-9]+)\//);
          var electionsMatch = href.match(/^\/elections\/([0-9]+)\//);
          
          if (_.isArray(adminMatch)) {
            authevent = adminId;
          } else if(_.isArray(boothMatch) && 2 === boothMatch.length) {
            authevent = boothMatch[1];
          } else if(_.isArray(electionsMatch) && 2 === electionsMatch.length) {
            authevent = electionsMatch[1];
          }
          return authevent;
        };

        authmethod.isAdmin = function() {
            return authmethod.isLoggedIn() && authmethod.admin;
        };

        authmethod.isLoggedIn = function() {
            var auth = $http.defaults.headers.common.Authorization;
            return auth && auth.length > 0;
        };

        authmethod.signup = function(data, authevent) {
            var eid = authevent || authId;
            return $http.post(backendUrl + 'auth-event/'+eid+'/register/', data);
        };

        authmethod.getUserInfo = function(userid) {
            if (!authmethod.isLoggedIn()) {
              var data = {
                success: function () { return data; },
                error: function (func) {
                  setTimeout(function() {
                    func({message:"not-logged-in"});
                  }, 0);
                  return data;
                }
              };
              return data;
            }
            if (typeof userid === 'undefined') {
                return $http.get(backendUrl + 'user/', {});
            } else {
                return $http.get(backendUrl + 'user/%d' % userid, {});
            }
        };

        authmethod.ping = function() {
            if (!authmethod.isLoggedIn()) {
              var data = {
                success: function () { return data; },
                error: function (func) {
                  setTimeout(function() {
                    func({message:"not-logged-in"});
                  }, 0);
                  return data;
                }
              };
              return data;
            }
            return $http.get(backendUrl + 'auth-event/'+authId+'/ping/');
        };

        authmethod.getImage = function(ev, uid) {
            return $http.get(backendUrl + 'auth-event/'+ev+'/census/img/'+uid+'/');
        };

        authmethod.login = function(data, authevent) {
            var eid = authevent || authId;
            delete data['authevent'];
            return $http.post(backendUrl + 'auth-event/'+eid+'/authenticate/', data);
        };

        authmethod.resendAuthCode = function(data, eid) {
            return $http.post(backendUrl + 'auth-event/'+eid+'/resend_auth_code/', data);
        };

        authmethod.getPerm = function(perm, object_type, object_id) {
            var data = {
                permission: perm,
                object_type: object_type,
                object_id: object_id + "" // to convert to string
            };
            return $http.post(backendUrl + 'get-perms/', data);
        };

        authmethod.viewEvent = function(id) {
            return $http.get(backendUrl + 'auth-event/' + id + '/');
        };

        authmethod.viewEvents = function() {
            return $http.get(backendUrl + 'auth-event/');
        };

        authmethod.createEvent = function(data) {
            return $http.post(backendUrl + 'auth-event/', data);
        };

        authmethod.editEvent = function(id, data) {
            return $http.post(backendUrl + 'auth-event/' + id +'/', data);
        };

        authmethod.addCensus = function(id, data, validation) {
            if (!angular.isDefined(validation)) {
              validation = "enabled";
            }
            var d = {
                "field-validation": validation,
                "census": data
            };
            return $http.post(backendUrl + 'auth-event/' + id + '/census/', d);
        };

        authmethod.getCensus = function(id, params) {
          if (!angular.isObject(params)) {
            return $http.get(backendUrl + 'auth-event/' + id + '/census/');
          }

          return $http.get(
            backendUrl + 'auth-event/' + id + '/census/',
            {params:params});
        };

        authmethod.getRegisterFields = function (viewEventData) {
          var fields = angular.copy(viewEventData.extra_fields);

          if (!fields) { fields = []; }
          var found = false;
          _.each(fields, function(field) {
            if (viewEventData.auth_method === "sms" && field.name === 'tlf') {
              if (field.type === 'text') {
                field.type = 'tlf';
              }
              found = true;
            } else if (viewEventData.auth_method === "email" && field.name === 'email') {
              found = true;
            }
          });

          if ((viewEventData.auth_method === "sms" || viewEventData.auth_method === "sms-otp") && !found) {
            fields.push({
              "name": "tlf",
              "type": "tlf",
              "required": true,
              "required_on_authentication": true
            });
          } else if (viewEventData.auth_method === "email" && !found) {
            fields.push({
              "name": "email",
              "type": "email",
              "required": true,
              "required_on_authentication": true
            });
          } else if (viewEventData.auth_method === "user-and-password") {
            fields.push({
              "name": "email",
              "type": "email",
              "required": true,
              "required_on_authentication": true
            });
            fields.push({
              "name": "password",
              "type": "password",
              "required": true,
              "required_on_authentication": true
            });
          }

          // put captcha the last
          for (var i=0; i<fields.length; i++) {
              if (fields[i]['type'] === "captcha") {
                  var captcha = fields.splice(i, 1);
                  fields.push(captcha[0]);
                  break;
              }
          }
          return fields;
        };

        authmethod.getLoginFields = function (viewEventData) {
            var fields = authmethod.getRegisterFields(viewEventData);
            if (viewEventData.auth_method === "sms" || viewEventData.auth_method === "email")
            {
              fields.push({
                "name": "code",
                "type": "code",
                "required": true,
                "required_on_authentication": true
              });
            } else if (viewEventData.auth_method === "sms-otp")
            {
              fields.push({
                "name": "code",
                "type": "code",
                "required": true,
                "steps": [1],
                "required_on_authentication": true
              });
            }

            fields = _.filter(fields, function (field) {return field.required_on_authentication;});

            // put captha the last
            for (var i=0; i<fields.length; i++) {
                if (fields[i]['type'] === "captcha") {
                    var captcha = fields.splice(i, 1);
                    fields.push(captcha[0]);
                    break;
                }
            }
            return fields;
        };

        authmethod.newCaptcha = function(message) {
            authmethod.captcha_status = message;
            return $http.get(backendUrl + 'captcha/new/', {})
              .success(function (data) {
                console.log(data);
                if (data.captcha_code !== null) {
                    authmethod.captcha_code = data.captcha_code;
                    authmethod.captcha_image_url = data.image_url;
                } else {
                    authmethod.captcha_status = 'Not found';
                }
              });
        };

        // TEST
        authmethod.test = function() {
            return $http.get(backendUrl);
        };

        authmethod.setAuth = function(auth, isAdmin, autheventid) {
            authmethod.admin = isAdmin;
            $http.defaults.headers.common.Authorization = auth;
            if (!authmethod.pingTimeout) {
                $interval.cancel(authmethod.pingTimeout);
                authmethod.launchPingDaemon(autheventid);
                authmethod.pingTimeout = $interval(
                        function() { authmethod.launchPingDaemon(autheventid); },
                        ConfigService.timeoutSeconds*500 // ms * 500 mean seconds * 1/2
                );
            }
            return false;
        };

        authmethod.electionsIds = function(page) {
            if (!page) {
                page = 1;
            }
            return $http.get(backendUrl + 'acl/mine/?object_type=AuthEvent&perm=edit|view&order=-pk&page='+page);
        };

        authmethod.sendAuthCodes = function(eid, election, user_ids, auth_method, extra) {
            var url = backendUrl + 'auth-event/'+eid+'/census/send_auth/';
            var data = {};
            if (angular.isDefined(election)) {
              data.msg = election.census.config.msg;
              if ('email' === auth_method) {
                data.subject = election.census.config.subject;
              }
            }
            if (angular.isDefined(user_ids)) {
              data["user-ids"] = user_ids;
            }
            if (angular.isDefined(auth_method)) {
              data["auth-method"] = auth_method;
            }
            if (extra) {
              data["extra"] = extra;
            }
            return $http.post(url, data);
        };

        authmethod.removeUsersIds = function(eid, election, user_ids) {
            var url = backendUrl + 'auth-event/'+eid+'/census/delete/';
            var data = {"user-ids": user_ids};
            return $http.post(url, data);
        };

        authmethod.activateUsersIds = function(eid, election, user_ids) {
            var url = backendUrl + 'auth-event/'+eid+'/census/activate/';
            var data = {"user-ids": user_ids};
            return $http.post(url, data);
        };

        authmethod.deactivateUsersIds = function(eid, election, user_ids) {
            var url = backendUrl + 'auth-event/'+eid+'/census/deactivate/';
            var data = {"user-ids": user_ids};
            return $http.post(url, data);
        };

        authmethod.changeAuthEvent = function(eid, st) {
            var url = backendUrl + 'auth-event/'+eid+'/'+st+'/';
            var data = {};
            return $http.post(url, data);
        };

        authmethod.launchPingDaemon = function(autheventid) {
          var postfix = "_authevent_" + autheventid;
          // only needed if it's an admin and daemon has not been launched
          if (!$cookies["isAdmin" + postfix]) {
            return;
          }
          authmethod.ping()
            .success(function(data) {
                $cookies["auth" + postfix] = data['auth-token'];
                authmethod.setAuth($cookies["auth" + postfix], $cookies["isAdmin" + postfix], autheventid);
            });
        };

        return authmethod;
    });

/**
 * Caching http response error to deauthenticate
 */
//angular.module('avRegistration').config(
//  function($httpProvider) {
//    $httpProvider.interceptors.push(function($q, $injector) {
//      return {
//        'responseError': function(rejection) {
//            if (rejection.data && rejection.data.error_codename &&
//              _.contains(
//                ['expired_hmac_key', 'empty_hmac', 'invalid_hmac_userid'],
//                rejection.data.error_codename))
//            {
//              $httpProvider.defaults.headers.common.Authorization = '';
//              $injector.get('$state').go("admin.logout");
//            }
//            return $q.reject(rejection);
//        }
//      };
//    });
//});

/**
 * IF the cookie is there we make the autologin
 */
//angular.module('avRegistration').run(function($cookies, $http, Authmethod) {
//    if ($cookies.auth) {
//        Authmethod.setAuth($cookies.auth, $cookies.isAdmin);
//    }
//});
