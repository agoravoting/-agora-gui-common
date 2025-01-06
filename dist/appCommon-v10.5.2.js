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

angular.module('avRegistration', ['ui.bootstrap','ui.utils','ui.router']);

angular.module('avRegistration').config(function() {
    /* Add New States Above */
});
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

    .factory('Authmethod', ["$http", "$cookies", "$window", "ConfigService", "$interval", "$state", "$location", "$document", "$q", function(
      $http,
      $cookies,
      $window,
      ConfigService,
      $interval,
      $state,
      $location,
      $document,
      $q
    ) {
        var backendUrl = ConfigService.authAPI;
        var authId = ConfigService.freeAuthId;
        var authmethod = {};
        authmethod.captcha_code = null;
        authmethod.captcha_image_url = "";
        authmethod.captcha_status = "";
        authmethod.admin = false;

        authmethod.decodeToken = function(token) {
          var parts = token.split("///");
          if (parts.length !== 2) {
              throw new Error("Invalid token format");
          }
      
          var messagePart = parts[1];
          var messageComponents = messagePart.split("/");
      
          if (messageComponents.length !== 2) {
              throw new Error("Invalid message format");
          }
      
          var message = messageComponents[1];
          var subParts = message.split(":");
      
          if (subParts.length < 4) {
              throw new Error("Invalid message format");
          }

          var subMessage = subParts.slice(0, subParts.length - 3).join(":");
          var expiryTimestamp = parseInt(subParts[subParts.length - 3], 10);
          var createTimestamp = parseInt(subParts[subParts.length - 1], 10);
      
          return {
              message: subMessage,
              create_timestamp: createTimestamp,
              expiry_timestamp: expiryTimestamp,
              expiry_secs_diff: expiryTimestamp - createTimestamp
          };
      };

        authmethod.getAuthevent = function() {
          var adminId = ConfigService.freeAuthId + '';
          var href = $location.path();
          var authevent = '';

          var adminMatch = href.match(/^\/admin\//);
          var boothMatch = href.match(/^\/booth\/([0-9]+)\//);
          var electionsMatch = href.match(/^\/(elections|election)\/([0-9]+)\//);

          if (_.isArray(adminMatch)) {
            authevent = adminId;
          } else if(_.isArray(boothMatch) && 2 === boothMatch.length) {
            authevent = boothMatch[1];
          } else if(_.isArray(electionsMatch) && 3 === electionsMatch.length) {
            authevent = electionsMatch[2];
          }
          return authevent;
        };

        function setupIdleDetection(callback)
        {
          var events = [
            'click',
            'keypress',
            'mousemove',
            'mousedown',
            'touchstart',
            'touchmove'
          ];
          events.forEach(function (event) {
              document.addEventListener(event, callback);
          });
        }

        function getAllTokens(isAdmin) {
          var credentialsStr = $window.sessionStorage.getItem("vote_permission_tokens");
          var tokens = [];
          if (credentialsStr) {
            var credentials = JSON.parse(credentialsStr);
            tokens = credentials
              .map(function (credential) { return credential.token; })
              .filter(function (token) { return !!token;});
            return tokens;
          }
          if (isAdmin && $http.defaults.headers.common.Authorization) {
            tokens.push($http.defaults.headers.common.Authorization);
          }
          return tokens;
        }
  
        function hasPassedHalfLifeExpiry(now, isAdmin) {
          var tokens = getAllTokens(isAdmin);
          if (0 === tokens.length) {
            return false;
          }
          var halfLifes = tokens.map(function (token) {
            var decodedToken = authmethod.decodeToken(token);
            return 1000 * (decodedToken.expiry_timestamp + decodedToken.create_timestamp)/2;
          });
          var minHalfLife = Math.min.apply(null, halfLifes);
          return minHalfLife < now;
        }

        authmethod.setAuth = function(auth, isAdmin, autheventid) {
            authmethod.admin = isAdmin;
            $http.defaults.headers.common.Authorization = auth;
            authmethod.lastAuthDate = new Date();

            if (authmethod.iddleDetectionSetup) {
              return;
            }

            function newInteractionCallback()
            {
              // Only try to renew token when it's older than 50% of
              // the expiration time
              var now = new Date();
              if (!hasPassedHalfLifeExpiry(now.getTime(), isAdmin)) {
                return;
              }
              authmethod.lastAuthDate = now;
              authmethod.refreshAuthToken(autheventid);
            }

            authmethod.iddleDetectionSetup = true;
            setupIdleDetection(newInteractionCallback);
            return false;
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
        
        authmethod.createLivePreview = function(data) {
          return $http.post(backendUrl + 'auth-event/live-preview/', data);
        };
        
        authmethod.getLivePreview = function(id) {
          var url = backendUrl + 'auth-event/'+ id + '/live-preview/';
          return $http.get(url);
        };

        authmethod.getUserInfoExtra = function() {
            if (!authmethod.isLoggedIn()) {
              var data = {
                then: function (onSuccess, onError) {
                  setTimeout(function() {
                    onError({data: {message:"not-logged-in"}});
                  }, 0);
                  return data;
                }
              };
              return data;
            }
            return $http.get(backendUrl + 'user/extra/', {});
        };

        /**
         * 
         * @returns the event with the highest id
         */
        authmethod.highestEvent = function()
        {
          var url = backendUrl + 'auth-event/highest/';
          return $http.get(url);
        };

        /**
         * @returns an activity page
         */
        authmethod.getActivity = function(eid, page, size, filterOptions, filterStr, receiver_id)
        {
            var params = {};
            var url = backendUrl + 'auth-event/' + eid + '/activity/';

            // 1. initialize GET params

            if (size === 'max') {
              params.n = 500;
            } else if (angular.isNumber(size) && size > 0 && size < 500) {
              params.n = parseInt(size);
            } else {
              params.n = 50;
            }

            if (!angular.isNumber(page)) {
                params.page = 1;
            } else {
                params.page = parseInt(page);
            }


            if (angular.isNumber(receiver_id)) {
                params.receiver_id = receiver_id;
            }

            _.extend(params, filterOptions);
            if (filterStr && filterStr.length > 0) {
                params.filter = filterStr;
            }

            // 2. generate request
            return $http.get(url, {params: params});
        };

        /**
         * @returns a page of ballot boxes
         */
        authmethod.getBallotBoxes = function(eid, page, size, filterOptions, filterStr)
        {
            var params = {};
            var url = backendUrl + 'auth-event/' + eid + '/ballot-box/';

            // 1. initialize GET params

            if (size === 'max') {
              params.n = 500;
            } else if (angular.isNumber(size) && size > 0 && size < 500) {
              params.n = parseInt(size);
            } else {
              params.n = 50;
            }

            if (!angular.isNumber(page)) {
                params.page = 1;
            } else {
                params.page = parseInt(page);
            }

            _.extend(params, filterOptions);
            if (filterStr && filterStr.length > 0) {
                params.filter = filterStr;
            }

            // 2. generate request
            return $http.get(url, {params: params});
        };

        /**
         * @returns the http request
         */
        authmethod.createBallotBox = function(eid, name)
        {
            var params = {name: name};
            var url = backendUrl + 'auth-event/' + eid + '/ballot-box/';

            return $http.post(url, params);
        };

        /**
         * @returns the http request
         */
        authmethod.obtainVoterAuthCode = function (electionId, username)
        {
          var params = {username: username};
          var url = backendUrl + 'auth-event/' + electionId + '/generate-auth-code/';

          return $http.post(url, params);
        };

        /**
         * @returns the http request
         */
        authmethod.resetVotersToPreRegistration = function (
          electionId, voterIds, comment
        ){
          var params = {
            "user-ids": voterIds,
            "comment": comment
          };
          var url = backendUrl + 'auth-event/' + electionId + '/census/reset-voter/';

          return $http.post(url, params);
        };

        /**
         * @returns the http request
         */
        authmethod.postTallySheet = function(eid, ballot_box_id, data)
        {
            var url = backendUrl + 'auth-event/' + eid + '/ballot-box/' + ballot_box_id + '/tally-sheet/';

            return $http.post(url, data);
        };

        /**
         * @returns the http request
         */
        authmethod.voteStats = function(eid)
        {
            var url = backendUrl + 'auth-event/' + eid + '/vote-stats/';

            return $http.get(url);
        };

        /**
         * @returns the http request
         */
         authmethod.suspend = function(eid)
         {
             var url = backendUrl + 'auth-event/' + eid + '/suspended/';

             return $http.post(url);
         };

        /**
         * @returns the http request
         */
         authmethod.resume = function(eid)
         {
             var url = backendUrl + 'auth-event/' + eid + '/resumed/';

             return $http.post(url);
         };

        /**
         * @returns the http request
         */
        authmethod.scheduledEvents = function(eid, scheduledEvents)
        {
          var url = backendUrl + 'auth-event/' + eid + '/scheduled-events/';
          return $http.post(url, scheduledEvents);
        };

        /**
         * @returns the http request
         */
        authmethod.getTallySheet = function(eid, ballot_box_id, tally_sheet_id)
        {
            var url = null;
            if (!tally_sheet_id) {
                url = backendUrl + 'auth-event/' + eid + '/ballot-box/' + ballot_box_id + '/tally-sheet/';
            } else {
              url = backendUrl + 'auth-event/' + eid + '/ballot-box/' + ballot_box_id + '/tally-sheet/' + tally_sheet_id + '/';
            }

            return $http.get(url);
        };

        /**
         * @returns the http request
         */
        authmethod.deleteTallySheet = function(eid, ballot_box_id, tally_sheet_id)
        {
            var url = backendUrl + 'auth-event/' + eid + '/ballot-box/' + ballot_box_id + '/tally-sheet/' + tally_sheet_id + "/";

            return $http.delete(url, {});
        };

        /**
         * @returns the http request
         */
        authmethod.deleteBallotBox = function(eid, ballot_box_id)
        {
            var url = backendUrl + 'auth-event/' + eid + '/ballot-box/' + ballot_box_id + "/delete/";

            return $http.delete(url, {});
        };

        authmethod.updateUserExtra = function (extra) {
            if (!authmethod.isLoggedIn()) {
              var data = {
                then: function (onSuccess, onError) {
                  setTimeout(function() {
                    onError({data: {message:"not-logged-in"}});
                  }, 0);
                  return data;
                }
              };
              return data;
            }
            return $http.post(backendUrl + 'user/extra/', extra);
        };

        authmethod.getUserInfo = function(userid) {
            if (!authmethod.isLoggedIn()) {
              var data = {
                then: function (onSuccess, onError) {
                  setTimeout(function() {
                    onError({data: {message:"not-logged-in"}});
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

        authmethod.ping = function(pingId) {
            if (!pingId) {
              pingId = authId;
            }
            if (!authmethod.isLoggedIn()) {
              var data = {
                then: function (onSuccess, onError) {
                  setTimeout(function() {
                    onError({data: {message:"not-logged-in"}});
                  }, 0);
                  return data;
                }
              };
              return data;
            }
            return $http.get(backendUrl + 'auth-event/'+pingId+'/ping/');
        };

        authmethod.getImage = function(ev, uid) {
            return $http.get(backendUrl + 'auth-event/'+ev+'/census/img/'+uid+'/');
        };

        authmethod.login = function(data, authevent) {
            var eid = authevent || authId;
            delete data['authevent'];
            return $http.post(backendUrl + 'auth-event/'+eid+'/authenticate/', data);
        };

        authmethod.authenticateOtl = function(data, authevent) {
            var eid = authevent || authId;
            delete data['authevent'];
            return $http.post(backendUrl + 'auth-event/'+eid+'/authenticate-otl/', data);
        };

        authmethod.censusQuery = function(data, authevent) {
          var eid = authevent || authId;
          delete data['authevent'];
          return $http.post(backendUrl + 'auth-event/'+eid+'/census/public-query/', data);
      };

        authmethod.resendAuthCode = function(data, eid) {
            return $http.post(backendUrl + 'auth-event/'+eid+'/resend_auth_code/', data);
        };

        authmethod.editChildrenParent = function(data, eid) {
            return $http.post(backendUrl + 'auth-event/'+eid+'/edit-children-parent/', data);
        };

        authmethod.getPerm = function(perm, object_type, object_id) {
            var data = {
                permission: perm,
                object_type: object_type,
                object_id: (object_id === null) ? object_id : object_id + "" // to convert to string
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
            var url = backendUrl + 'auth-event/' + id + '/census/';

            return $http({
              method : "POST",
              url : url,
              timeout: ConfigService.serverTimeoutSeconds * 1000,
              data: d
            });
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
          var fields = _.filter(
            angular.copy(viewEventData.extra_fields),
            function (item) {
              if (true === item.required_when_registered) {
                return false;
              }
              return true;
            });

          if (!fields) { fields = []; }

          // put captcha the last
          for (var i = 0; i < fields.length; i++) {
            if (fields[i]['type'] === "captcha") {
              var captcha = fields.splice(i, 1);
              fields.push(captcha[0]);
              break;
            }
          }
          return fields;
        };

        authmethod.hasOtpCodeField = function (viewEventData)
        {
          var fields = authmethod.getRegisterFields(
            viewEventData
          );
          for (var i=0; i<fields.length; i++) {
            if (fields[i]['type'] === "otp-code") {
              return true;
            }
          }

          return false;
        };

        authmethod.getCensusQueryFields = function (viewEventData)
        {
            var fields = angular.copy(viewEventData.extra_fields);

            fields = _.filter(
                fields,
                function (field) {
                    return field.required_on_authentication;
                }
            );

            return fields;
        };

        authmethod.getOtlFields = function (viewEventData)
        {
            var fields = angular.copy(viewEventData.extra_fields);

            fields = _.filter(
                fields,
                function (field) {
                    return field.match_against_census_on_otl_authentication;
                }
            );

            return fields;
        };

        authmethod.getLoginWithCode = function (_viewEventData) {
          return [
            {
              "name": "__username",
              "type": "text",
              "required": true,
              "min": 3, 
              "max": 200,
              "required_on_authentication": true
            },
            {
              "name": "code",
              "type": "code",
              "required": true,
              "required_on_authentication": true
            }
          ];
        };

        authmethod.getLoginFields = function (viewEventData) {
            var fields = authmethod.getRegisterFields(
              viewEventData
            );
            var hasOtpCodeField = authmethod.hasOtpCodeField(viewEventData);

            if (_.contains(["sms", "email"], viewEventData.auth_method))
            {
              fields.push({
                "name": "code",
                "type": "code",
                "required": true,
                "required_on_authentication": true
              });
            } else if (
              hasOtpCodeField ||
              _.contains(["sms-otp", "email-otp"], viewEventData.auth_method)
            ) {
              fields.push({
                "name": "code",
                "type": "code",
                "required": true,
                "steps": [1],
                "required_on_authentication": true
              });
            }

            fields = _.filter(
              fields, 
              function (field) {return field.required_on_authentication;}
            );

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
              .then(function (response) {
                console.log(response.data);
                if (response.data.captcha_code !== null) {
                    authmethod.captcha_code = response.data.captcha_code;
                    authmethod.captcha_image_url = response.data.image_url;
                } else {
                    authmethod.captcha_status = 'Not found';
                }
              });
        };

        // TEST
        authmethod.test = function() {
            return $http.get(backendUrl);
        };

        authmethod.electionsIds = function(page, listType, ids, page_size) {
            if (!page) {
                page = 1;
            }
            if (!listType) {
              listType = 'all';
            }
            
            // default perms to request
            var perms = 'edit|view';
            if (listType === 'archived') {
              perms = 'unarchive|view-archived';
            }
            // only if needed
            var queryIds = '';
            if (!!ids) {
              queryIds = '&ids=' + ids.join('|');
            } else {
              queryIds = '&only_parent_elections=true';
            }
            if (!!page_size) {
              queryIds += '&n=' + page_size;
            }

            return $http.get(
              backendUrl + 
              'auth-event/?has_perms=' +
              perms +
              queryIds +
              '&order=-pk&page=' +
              page
            );
        };

        authmethod.sendAuthCodes = function(eid, election, user_ids, auth_method, extra, filter, force_create_otp) {
            var url = backendUrl + 'auth-event/'+eid+'/census/send_auth/';
            var data = {};
            if (angular.isDefined(election)) {
              data.msg = election.census.config.msg;
              if ('email' === auth_method || 'email-otp' === auth_method) {
                data.subject = election.census.config.subject;
                if (ConfigService.allowHtmlEmails &&
                    election.census.config.html_message) {
                  data.html_message = election.census.config.html_message;
                }
              }
            }
            if (angular.isDefined(user_ids)) {
              data["user-ids"] = user_ids;
            }
            if (angular.isDefined(auth_method)) {
              data["auth-method"] = auth_method;
            }
            if (angular.isDefined(force_create_otp)) {
              data["force_create_otl"] = force_create_otp;
            }
            if (extra) {
              data["extra"] = extra;
            }
            if (angular.isDefined(filter)) {
              data["filter"] = filter;
            }
            return $http.post(url, data);
        };

        authmethod.removeUsersIds = function(eid, election, user_ids, comment) {
            var url = backendUrl + 'auth-event/'+eid+'/census/delete/';
            var data = {"user-ids": user_ids};
            if (comment) {
              data['comment'] = comment;
            }
            return $http.post(url, data);
        };

        authmethod.activateUsersIds = function(eid, election, user_ids, comment) {
            var url = backendUrl + 'auth-event/'+eid+'/census/activate/';
            var data = {"user-ids": user_ids, "comment": comment};
            return $http.post(url, data);
        };

        authmethod.deactivateUsersIds = function(eid, election, user_ids, comment) {
            var url = backendUrl + 'auth-event/'+eid+'/census/deactivate/';
            var data = {"user-ids": user_ids, "comment": comment};
            return $http.post(url, data);
        };

        authmethod.changeAuthEvent = function(eid, st, data) {
            var url = backendUrl + 'auth-event/'+eid+'/'+st+'/';
            if (data === undefined) {
              data = {};
            }
            return $http.post(url, data);
        };

        authmethod.allowTally = function(eid) {
            var url = backendUrl + 'auth-event/'+eid+'/allow-tally/';
            var data = {};
            return $http.post(url, data);
        };

        authmethod.unpublishResults = function(eid) {
            var url = backendUrl + 'auth-event/'+eid+'/unpublish-results/';
            var data = {};
            return $http.post(url, data);
        };

        authmethod.archive = function(eid) {
            var url = backendUrl + 'auth-event/'+eid+'/archive/';
            var data = {};
            return $http.post(url, data);
        };

        authmethod.unarchive = function(eid) {
            var url = backendUrl + 'auth-event/'+eid+'/unarchive/';
            var data = {};
            return $http.post(url, data);
        };

        authmethod.setPublicCandidates = function(eid, makePublic) {
          var url = backendUrl + 'auth-event/'+eid+'/set-public-candidates/';
          var data = {
            publicCandidates: makePublic
          };
          return $http.post(url, data);
        };

        authmethod.setInsideOtlPeriod = function(eid, insideOtlPeriod) {
          var url = backendUrl + 'auth-event/'+eid+'/set-authenticate-otl-period/';
          var data = {
            set_authenticate_otl_period: insideOtlPeriod
          };
          return $http.post(url, data);
        };

        authmethod.launchTally = function(
          electionId,
          tallyElectionIds,
          forceTally,
          mode
        ) {
            var url = backendUrl + 'auth-event/' + electionId + '/tally-status/';
            var data = {
              children_election_ids: tallyElectionIds,
              force_tally: forceTally,
              mode: mode
            };
            return $http.post(url, data);
        };

        var lastRefreshMs = 0;
        authmethod.refreshAuthToken = function(autheventid) {
          var deferred = $q.defer();
          var jnow = Date.now();
          if (jnow - lastRefreshMs < 1000) {
            deferred.reject("ongoing refresh");
            return deferred.promise;
          } else {
            lastRefreshMs = jnow;
          }
          var postfix = "_authevent_" + autheventid;
          // ping daemon is not active for normal users

          /*if (!authmethod.admin) {
            var hasGracefulPeriod = window.sessionStorage.getItem('hasGracefulPeriod');
            if (hasGracefulPeriod === "true") {
              deferred.reject("not an admin");
              return deferred.promise;
            }
          }*/
          // if document is hidden, then do not update the cookie, and redirect
          // to admin logout if cookie expired
          if (document.visibilityState === 'hidden') {
            if (!$cookies.get("auth" + postfix)) {
              $state.go("admin.logout");
            }
            deferred.reject("tab not focused");
            return deferred.promise;
          }
          var now = Date.now();
          var sessionStartedAtMs = now;
          return authmethod.ping(autheventid)
            .then(function(response) {
                var options = {};
                var authToken = response.data['auth-token'];
                if (authToken) {
                  var decodedToken = authmethod.decodeToken(authToken);
                  options.expires = new Date(now + 1000 * decodedToken.expiry_secs_diffs);
                  // update cookies expiration
                  $cookies.put(
                    "auth" + postfix,
                    response.data['auth-token'],
                    options
                  );
                  $cookies.put(
                    "isAdmin" + postfix,
                    $cookies.get("isAdmin" + postfix),
                    options
                  );
                  $cookies.put(
                    "userid" + postfix,
                    $cookies.get("userid" + postfix),
                    options
                  );
                  $cookies.put(
                    "userid" + postfix,
                    $cookies.get("userid" + postfix),
                    options
                  );
                  $cookies.put(
                    "user" + postfix,
                    $cookies.get("user" + postfix),
                    options
                  );
                  authmethod.setAuth(
                    $cookies.get("auth" + postfix),
                    $cookies.get("isAdmin" + postfix),
                    autheventid
                  );
                }

                // if it's an election with no children elections
                if (angular.isDefined(response.data['vote-permission-token']))
                  {
                    var accessToken = response.data['vote-permission-token'];
                    var decodedAccessToken = authmethod.decodeToken(accessToken);
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
                  }
                  // if it's an election with children elections then show access to them
                  else if (angular.isDefined(response.data['vote-children-info']))
                  {
                    // assumes the iam response has the same children 
                    var tokens = _
                      .chain(response.data['vote-children-info'])
                      .map(function (child, index) {
                        var accessToken = child['vote-permission-token'];
                        var decodedAccessToken = accessToken && authmethod.decodeToken(accessToken) || null;
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
                  }
            });
        };

        authmethod.getUserDraft = function () {
            if (!authmethod.isLoggedIn()) {
              var data = {
                then: function (onSuccess, onError) {
                  setTimeout(function() {
                    onError({data: {message:"not-logged-in"}});
                  }, 0);
                  return data;
                }
              };
              return data;
            }
            return $http.get(backendUrl + 'user/draft/', {});
        };

        authmethod.uploadUserDraft = function (draft) {
            if (!authmethod.isLoggedIn()) {
              var data = {
                then: function (onSuccess, onError) {
                  setTimeout(function() {
                    onError({data: {message:"not-logged-in"}});
                  }, 0);
                  return data;
                }
              };
              return data;
            }
            var draft_data = {
              'draft_election': draft
            };
            return $http.post(backendUrl + 'user/draft/', draft_data);
        };

        authmethod.launchSelfTestTask = function() {
          return $http.post(backendUrl + 'tasks/launch-self-test/', {});
        };

        authmethod.getTasks = function(params) {
          var url = backendUrl + 'tasks/';
          if (!angular.isObject(params)) {
            return $http.get(url);
          }

          return $http.get(url, {params:params});
        };

        authmethod.getTask = function(id) {
          var url = backendUrl + 'tasks/' + id + '/';
          return $http.get(url);
        };

        authmethod.cancelTask = function(id) {
          var url = backendUrl + 'tasks/' + id + '/cancel/';
          return $http.post(url, {});
        };

        authmethod.getTurnout = function (id) {
          var url = backendUrl + 'auth-event/' + id + '/turnout/';
          return $http.get(url);
        };

        return authmethod;
    }]);

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
  .controller(
    'LoginController',
    ["$scope", "$stateParams", "Authmethod", function(
      $scope,
      $stateParams,
      Authmethod
    ) {
      $scope.alt_methods = [];
      if (!$stateParams.altmethod) {
        Authmethod
          .viewEvent($stateParams.id)
          .then(
            function onSuccess(response) {
              if (response.data.status !== "ok") {
                return;
              }
              $scope.alt_methods = response
                .data
                .events
                .alternative_auth_methods
                .filter(function (auth_method) {
                  return auth_method.auth_method_name !== 'smart-link';
                })
                .map(function (auth_method) {
                  return auth_method.id;
                });
            }
          );
      }

      $scope.event_id = $stateParams.id;
      $scope.code = $stateParams.code;
      $scope.email = $stateParams.email;
      $scope.username = $stateParams.username;
      $scope.isOpenId = $stateParams.isOpenId;
      $scope.withCode = $stateParams.withCode;
      $scope.withAltMethod = $stateParams.withAltMethod;
      $scope.selectedAltMethod = $stateParams.altmethod;
      $scope.isOtl = $stateParams.isOtl;
      $scope.otlSecret = $stateParams.otlSecret;
    }]
  );

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
    ["Authmethod", "StateDataService", "$state", "$location", "$cookies", "$window", "$timeout", "ConfigService", "Patterns", function(
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
              !scope.isOpenId &&
              (authevent.auth_method !== 'openid-connect') &&
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
  }]);

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

angular.module('avRegistration').controller('LogoutController',
  ["$scope", "$stateParams", "$filter", "ConfigService", "$state", "$cookies", "Authmethod", function($scope, $stateParams, $filter, ConfigService, $state, $cookies, Authmethod) {
    var adminId = ConfigService.freeAuthId;
    var authevent = Authmethod.getAuthevent();
    var postfix = "_authevent_" + authevent;
    $cookies.put("user" + postfix, '');
    $cookies.put("auth" + postfix, '');
    $cookies.put("authevent_" + authevent, '');
    $cookies.put("userid" + postfix, '');
    $cookies.put("isAdmin" + postfix, false);
    if (authevent === ConfigService.freeAuthId + '' || !authevent) {
        $state.go("admin.login");
    } else {
        $state.go("registration.login", {id: $cookies.get("authevent_" + authevent)});
    }
  }]
);

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

angular.module('avRegistration').controller('RegisterController',
  ["$scope", "$stateParams", "$filter", "ConfigService", function($scope, $stateParams, $filter, ConfigService) {
    $scope.event_id = $stateParams.id;
    $scope.email = $stateParams.email;
  }]
);

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
  .directive('avRegister', ["Authmethod", "StateDataService", "$parse", "$state", "ConfigService", "$cookies", "$window", "$sce", function(Authmethod, StateDataService, $parse, $state, ConfigService, $cookies, $window, $sce) {
    // we use it as something similar to a controller here
    function link(scope, element, attrs) {
        var autheventid = attrs.eventId;
        scope.dnieurl = ConfigService.dnieUrl + autheventid + '/';
        scope.register = {};
        scope.sendingData = false;
        scope.admin = false;
        scope.error = null;

        scope.email = null;
        if (attrs.email && attrs.email.length > 0) {
          scope.email = attrs.email;
        }

        if ("admin" in attrs) {
          scope.admin = true;
        }

        scope.getLoginDetails = function (eventId) {
          if (!scope.admin) {
              return {
                path: 'election.public.show.login_email',
                data: {id: eventId, email: scope.email}
              };
          } else {
              return {path: 'admin.login_email', data:{email: scope.email}};
          }
        };

        scope.signUp = function(valid) {
            if (!valid) {
                return;
            }
            scope.sendingData = true;
            scope.error = null;
            var data = {
                'captcha_code': Authmethod.captcha_code,
            };
            _.each(scope.register_fields, function (field) {
              data[field.name] = field.value;
              if (field.name === 'email' && _.contains(['email', 'email-otp'], scope.method))
              {
                scope.email = field.value;
              }
              else if (field.name === 'tlf' &&
                _.contains(['sms', 'sms-otp'], scope.method))
              {
                scope.email = field.value;
              }
            });
            var details;
            Authmethod.signup(data, autheventid)
                .then(
                  function onSuccess(response) {
                    details = scope.getLoginDetails(autheventid);
                    if (response.data.status === "ok") {
                        scope.user = response.data.user;
                        data.successfulRegistration = true;
                        StateDataService.go(details.path, details.data, data);
                        scope.error = response.data.msg || $sce.trustAsHtml($window.i18next.t('avRegistration.invalidRegisterData', {
                          url: $state.href(details.path, details.data)
                        }));
                    } else {
                        scope.sendingData = false;
                        scope.status = 'Not found';
                        scope.error = response.data.msg || $sce.trustAsHtml($window.i18next.t('avRegistration.invalidRegisterData', {
                          url: $state.href(details.path, details.data)
                        }));
                    }
                  },
                  function onError(response) {
                    details = scope.getLoginDetails(autheventid);
                    scope.sendingData = false;
                    scope.status = 'Registration error: ' + response.data.message;

                    if (!!response.data.error_codename && response.data.error_codename === 'invalid-dni') {
                      scope.error = $sce.trustAsHtml($window.i18next.t('avRegistration.invalidRegisterDNI'));
                    } else {
                        scope.error = response.data.msg || $sce.trustAsHtml($window.i18next.t('avRegistration.invalidRegisterData', {
                          url: $state.href(details.path, details.data)
                        }));
                        if (response.data.msg === 'Invalid captcha') {
                            Authmethod.newCaptcha();
                        }
                    }
                  }
                );
        };

        scope.goLogin = function(event) {
          console.log("goLogin");
          if (event) {
            event.preventDefault();
            event.stopPropagation();
          }

          if (!scope.authevent) {
            return;
          }

          if (scope.authevent['id'] === ConfigService.freeAuthId) {
              $state.go("admin.login");
          } else {
              $state.go("election.public.show.login", {id: scope.authevent['id']});
          }
        };

        scope.apply = function(authevent) {
            scope.method = authevent['auth_method'];
            scope.name = authevent['name'];
            scope.authevent = authevent;

            // if registration is closed, redirect to login
            if (authevent['census'] !== 'open' || scope.method === 'openid-connect') {
              if (authevent['id'] === ConfigService.freeAuthId) {
                  $state.go("admin.login");
              } else {
                  $state.go("election.public.show.login", {id: authevent['id']});
              }
            }
            scope.register_fields = Authmethod.getRegisterFields(authevent);
            var fields = _.map(
              scope.register_fields,
              function (el) {
                el.value = null;
                el.disabled = false;
                if (el.type === "email" && scope.email !== null) {
                  el.value = scope.email;
                  el.disabled = true;
                }
                return el;
              });
        };

        scope.view = function(id) {
            Authmethod.viewEvent(id)
                .then(
                  function onSuccess(response) {
                    if (response.data.status === "ok") {
                        scope.apply(response.data.events);
                    } else {
                        scope.status = 'Not found';
                        document.querySelector(".input-error").style.display = "block";
                    }
                  },
                  function onError(response) {
                    scope.status = 'Scan error: ' + response.data.message;
                    document.querySelector(".input-error").style.display = "block";
                  }
                );
        };

        scope.view(autheventid);
    }

    return {
      restrict: 'AE',
      scope: true,
      link: link,
      templateUrl: 'avRegistration/register-directive/register-directive.html'
    };
  }]);

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
    .factory('Patterns', function() {
        var patterns = {};
        patterns.get = function(name) {
            if (name === 'dni') {
                return /^\d{7,8}[a-zA-Z]{1}$/i;
            } else if (name === 'mail' || name === 'email') {
                return /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
            } else {
                return /.*/;
            }
        };
        return patterns;
    });

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

/**
 * Shows a field
 */
angular.module('avRegistration')
  .directive('avrField', ["$state", function($state) {
    function link(scope, element, attrs) {
      console.log("type = " + scope.field.type);
      scope.index = attrs.index;
    }

    return {
      restrict: 'AE',
      scope: true,
      link: link,
      templateUrl: 'avRegistration/field-directive/field-directive.html'
    };
  }]);

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
  .directive('avrEmailField', ["$state", "Patterns", function($state, Patterns) {
    function link(scope, element, attrs) {
      scope.emailRe = Patterns.get('email');
    }
    return {
      restrict: 'AE',
      link: link,
      scope: true,
      templateUrl: 'avRegistration/fields/email-field-directive/email-field-directive.html'
    };
  }]);

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
  .directive('avrDateField', ["$state", "Patterns", function($state, Patterns) {
    function link(scope, element, attrs) {
        scope.years = [];
        scope.months = [];
        scope.field = scope.$parent.field;
        scope.date = null;

        function initializeValue() {
          var dateValue = null;
          if (
            scope.field.value === undefined ||
            scope.field.value === null ||
            scope.field.value.length === 0
          ) {
            dateValue = new Date();
          } else {
            var data = scope.field.value.split('-');
            dateValue = new Date(data[0], parseInt(data[1]) - 1, data[2]);
          }
          scope.date = {
            year: dateValue.getFullYear(),
            month: dateValue.getMonth() + 1,
            day: dateValue.getDate()
          };
        }
        initializeValue();

        scope.getYears = function () {
          var initY = (new Date()).getFullYear();
          var i = 0;
          var years = [];
 
          for (i=initY; i>=initY-130; i--) {
            years.push(i);
          }
          return years;
        };

        scope.getMonths = function () {
          var i = 0;
          var months = [];
  
          for (i=1; i<=12; i++) {
            months.push(i);
          }
          return months;
        };

        scope.getDays = function() {
          var days = [];
          var i = 0;
          var ndays = (new Date(scope.date.year, scope.date.month, 0)).getDate();
          for (i=1; i<=ndays; i++) {
            days.push(i);
          }
          return days;
        };

        function numberPadStart(num, size) {
          var str = "000000000" + num;
          return str.substr(str.length - size);
        }

        scope.onChange = function() {
          var monthStr = numberPadStart(scope.date.month, 2);
          var dayStr = numberPadStart(scope.date.day, 2);
          scope.field.value = scope.date.year + "-" + monthStr + "-" + dayStr;
        };

        // initial value update
        scope.onChange();
    }
    return {
      restrict: 'AE',
      link: link,
      scope: {
        label: '=',
      },
      templateUrl: 'avRegistration/fields/date-field-directive/date-field-directive.html'
    };
  }]);

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
  .directive('avrPasswordField', ["$state", function($state) {
    return {
      restrict: 'AE',
      scope: true,
      templateUrl: 'avRegistration/fields/password-field-directive/password-field-directive.html'
    };
}]);
angular.module('avRegistration')
  .directive('avrTextField', ["$state", function($state) {
    function link(scope, element, attrs) {
      if (angular.isUndefined(scope.field.regex)) {
        scope.re = new RegExp("");
      } else {
        scope.re = new RegExp(scope.field.regex);
      }
    }
    return {
      restrict: 'AE',
      link: link,
      scope: true,
      templateUrl: 'avRegistration/fields/text-field-directive/text-field-directive.html'
    };
  }]);

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
  .directive('avrDniField', ["$state", function($state) {
    function link(scope, element, attrs) {
      var dni_re = /^([0-9]{1,8}[A-Z]|[LMXYZ][0-9]{1,7}[A-Z])$/;

      /**
       * Normalizes dnis, using uppercase, removing characters not allowed and
       * left-side zeros
       */
      function normalize_dni(dni) {
        if (!dni) {
          return "";
        }

        var allowed_chars = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890";
        var dni2 = dni.toUpperCase();
        var dni3 = "";
        for (var i = 0; i < dni2.lenth; i++) {
          var char = dni2[i];
          if (allowed_chars.indexOf(char) >= 0) {
            dni3 += char;
          }
        }
        var numbers = "1234567890";
        var last_char = "";
        var dni4 = "";
        for (var j = 0; j < dni3.lenth; j++) {
          var char2 = dni3[j];
          if ((last_char==="" || '1234567890'.indexOf(last_char) === -1) && char2 === '0') {
          }
          dni4 += char2;
          last_char = char2;
        }
        return dni4;
      }

      // returns true if regex matches or if there's no regex
      scope.validateDni = function(dni) {
        var norm_dni = normalize_dni(dni);

        if (!norm_dni.match(dni_re)) {
          return true;
        }

        var prefix = norm_dni.charAt(0);
        var index = "LMXYZ".indexOf(prefix);
        var niePrefix = 0;
        if (index > -1) {
          niePrefix = index;
          norm_dni = norm_dni.substr(1);
          if (prefix === 'Y') {
              norm_dni = "1" + norm_dni;
          } else if (prefix === 'Z') {
              norm_dni = "2" + norm_dni;
          }
        }
        var dni_letters = "TRWAGMYFPDXBNJZSQVHLCKE";
        var letter = dni_letters.charAt( parseInt( norm_dni, 10 ) % 23 );
        return letter === norm_dni.charAt(norm_dni.length - 1);
      };
    }
    return {
      restrict: 'AE',
      link: link,
      scope: true,
      templateUrl: 'avRegistration/fields/dni-field-directive/dni-field-directive.html'
    };
  }]);

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
  .directive('avrCodeField', ["$state", "Plugins", function($state, Plugins) {
    function link(scope, element, attrs) {
      scope.codePattern = /[abcdefghjklmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-]{8,9}/;
      var rand_code = '' + _.random(1e12);
      scope.code_id = 'input' + scope.index + rand_code;

      scope.showResendAuthCode = function ()
      { 
        var data = {showUserSendAuthCode: true};
        Plugins.hook('hide-user-send-auth-code', data);
        return data.showUserSendAuthCode;
      };

      // TODO: validate email for email-otp. For now, we just allow the resend
      // button for that use-case
      if (_.contains(['sms', 'sms-otp'], scope.method)) {
        var telInput =
          angular.element(document.getElementById('input' + scope.telIndex));
        scope.isValidTel = telInput.intlTelInput("isValidNumber");
        scope.$watch('telField.value',
          function (newValue, oldValue) {
            scope.isValidTel = telInput.intlTelInput("isValidNumber");
          },
          true);
      }
    }
    return {
      restrict: 'AE',
      scope: true,
      link: link,
      templateUrl: 'avRegistration/fields/code-field-directive/code-field-directive.html'
    };
  }]);

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
  .directive('avrTelField', ["$state", "$timeout", function($state, $timeout) {
    function link(scope, element, attrs) {

      scope.tlfPattern = /^[+]?\d{9,14}$/;
      scope.isValidNumber = true;

      // lookup ip data and send callbacks when it is available

      var ipData = null;
      var ipCallbacks = [];
      $.get('https://ipinfo.io', function() {}, "jsonp")
      .always(function(resp) {
          ipData = resp;
          for (var i = 0; i < ipCallbacks.length; i++) {
            ipCallbacks[i]();
          }
        });

      $timeout(function() {
        /* configure registration telephone phone number */
        var telInput = angular.element(document.getElementById("input" + scope.index));
        // initialise plugin
        telInput.intlTelInput({
          utilsScript: "election/utils.js",
          separateDialCode: true,
          initialCountry: "auto",
          preferredCountries: ["es", "gb", "us"],
          autoPlaceholder: "aggressive",
          placeholderNumberType: "MOBILE",
          geoIpLookup: function(callback) {
              var applyCountry = function()
              {
                var countryCode = (ipData && ipData.country) ? ipData.country : "es";
                callback(countryCode);
              };
              if (ipData) {
                applyCountry();
              } else {
                ipCallbacks.push(applyCountry);
              }
            }
          });
          if (_.isString(scope.field.value) && 0 < scope.field.value.length) {
            telInput.intlTelInput("setNumber", scope.field.value);
          }

          var validateTel = function()
          {
            scope.$evalAsync(function() {
              var intlNumber = telInput.intlTelInput("getNumber");
              if (intlNumber) {
                scope.field.value = intlNumber;
              }
              var isValid = telInput.intlTelInput("isValidNumber");
              if (!isValid && $("#input"+ scope.index).val().replace("[ \t\n]", "").length > 0)
              {
                telInput.toggleClass("error", true);
                scope.isValidNumber = false;
              } else
              {
                telInput.toggleClass("error", false);
                scope.isValidNumber = true;
              }
            });
          };
          // on keyup / change flag: reset
          telInput.on("keyup change", validateTel);
      });
    }
    return {
      restrict: 'AE',
      scope: true,
      link: link,
      templateUrl: 'avRegistration/fields/tel-field-directive/tel-field-directive.html'
    };
  }]);

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
  .directive('avrBoolField', ["$state", function($state) {
    return {
      restrict: 'AE',
      scope: true,
      templateUrl: 'avRegistration/fields/bool-field-directive/bool-field-directive.html'
    };
  }]);

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
  .directive('avrIntField', ["$state", function($state) {
    function link(scope, element, attrs) {
      if (angular.isUndefined(scope.field.regex)) {
        scope.re = new RegExp("");
      } else {
        scope.re = new RegExp(scope.field.regex);
      }
    }
    return {
      restrict: 'AE',
      link: link,
      scope: true,
      templateUrl: 'avRegistration/fields/int-field-directive/int-field-directive.html'
    };
  }]);

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
  .directive('avrCaptchaField', ['Authmethod', '$state', '$interval', function(Authmethod, $state, $interval) {
    function link(scope, element, attrs) {
        var timeoutId = null;

        scope.authMethod = Authmethod;
        Authmethod.newCaptcha("");
    }

    return {
      restrict: 'AE',
      scope: true,
      link: link,
      templateUrl: 'avRegistration/fields/captcha-field-directive/captcha-field-directive.html'
    };
  }]);

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
  .directive('avrTextareaField', ["$state", function($state) {
    return {
      restrict: 'AE',
      scope: true,
      templateUrl: 'avRegistration/fields/textarea-field-directive/textarea-field-directive.html'
    };
  }]);

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
  .directive('avrImageField', ["$state", "$timeout", function($state, $timeout) {
    function link(scope, element, attrs) {
        function readImage(input) {
            if ( input.files && input.files[0] ) {
                var FR = new FileReader();
                FR.onload = function(e) {
                     scope.field.value = e.target.result;
                };
                FR.readAsDataURL( input.files[0] );
            }
        }

        $timeout(function() {
            $("#image-field").change(function() { readImage( this ); });
        }, 0);
    }

    return {
      restrict: 'AE',
      link: link,
      scope: true,
      templateUrl: 'avRegistration/fields/image-field-directive/image-field-directive.html'
    };
  }]);

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

/**
 * @description Service that manages the Plugins extension points.
 *
 * These are the hooks called by admin-console:
 *
 * - Name: election-modified
 *
 *   Description: called by @a ElectionsApi.setCurrent service before the new
 *   election is set.
 *
 *   Input data: {
 *      // old election object (before setCurrent was called)
 *      "old": Election,
 *
 *      // old new election object that is going to be set
 *      "el": Election
 *   }
 *
 * - Name: send-auth-codes-steps
 *
 *   Description: called by @a SendMsg.calculateSteps service before calculating
 *   the number of steps of the send authentication codes dialog. It's a good
 *   way of modifying @a SendMsg.steps.extra.
 *
 *   Input data: {
 *      // current election object
 *      "el": Election,
 *
 *      // ids of the electorate to which the authentication message is going
 *      // to be set. Might be null if it's all the electorate.
 *      "user_ids": List[Integer]
 *   }
 *
 * - Name: send-auth-codes-confirm-extra
 *
 *   Description: called by @a SendMsg.confirmAuthCodesModal service before
 *   showing the @a SendAuthCodesModalConfirm window when sending authentication
 *   codes to the electorate. This hook allows to set some html to be shown in
 *   the modal window. Note that the html will not be trusted unless you
 *   explicitly make it trusted with @a $sce.
 *
 *   Input data: {
 *      // modifiable list of html strings to shown in the modal confirm window.
 *      // starts empty, but other hook handlers might modify it. It's used as
 *      // the hook's output.
 *      "html": []
 *   }
 *
 * - Name: send-auth-codes-confirm-close
 *
 *   Description: Called by @a .confirmAuthCodesModal service after
 *   closing the @a SendAuthCodesModalConfirm window to process the result of
 *   the modal (this result is the input of the hook) and decide what to do.
 *
 *   Input data: string
 *
 * - Name: send-auth-codes-pre
 *
 *   Description: Called by @a SendMsg.sendAuthCodes before sending auth codes.
 *   Used to decide whether or not to send them - if any hook handler returns
 *   a value interpretable as false, won't send it.
 *
 *   Input data: {
 *      // current election object
 *      "el": Election,
 *
 *      // ids of the electorate to which the authentication message is going
 *      // to be set. Might be null if it's all the electorate.
 *      "user_ids": List[Integer]
 *   }
 *
 * - Name: send-auth-codes-success
 *
 *   Description: Called by @a SendMsg.sendAuthCodes after sending auth codes
 *   when the sending was successful.
 *
 *   Input data: {
 *      // current election object
 *      "el": Election,
 *
 *      // ids of the electorate to which the authentication message is going
 *      // to be set. Might be null if it's all the electorate.
 *      "ids": List[Integer]
 *
 *      // response object from jquery
 *      "response": ResponseObject
 *   }
 *
 * - Name: send-auth-codes-error
 *
 *   Description: Called by @a SendMsg.sendAuthCodes after sending auth codes
 *   when the sending had an error.
 *
 *   Input data: {
 *      // current election object
 *      "el": Election,
 *
 *      // ids of the electorate to which the authentication message is going
 *      // to be set. Might be null if it's all the electorate.
 *      "ids": List[Integer]
 *
 *      // response object from jquery
 *      "response": ResponseObject
 *
 * - Name: add-to-census-pre
 *
 *   Description: Called by @a avAdminElcensus.censusCall just before adding
 *   some electors to the election. A hook handler can cancel the add to census
 *   action return a value interpretable as false.
 *
 *   // List of electors that are about to be added
 *   Input data: List[NewElectorMetadata]
 *
 * - Name: add-to-census-success
 *
 *   Description: Called by @a avAdminElcensus.censusCall after adding
 *   some electors to the election when the call to the API was successful.
 *   Allows the hook handler process the api result.
 *
 *   Input data: {
 *      // List of electors that are about to be added
 *      "data": List[NewElectorMetadata],
 *
 *      // response object from jquery
 *      "response": ResponseObject
 *   }
 *
 * - Name: add-to-census-error
 *
 *   Description: Called by @a avAdminElcensus.censusCall after adding
 *   some electors to the election when the call to the api produced an error.
 *   Allows the hook handler process the api result.
 *
 *   Input data: {
 *      // List of electors that are about to be added
 *      "data": List[NewElectorMetadata],
 *
 *      // response object from jquery
 *      "response": ResponseObject
 *   }
 */
angular.module('avRegistration')
    .factory('Plugins', function() {
        var plugins = {};
        // TODO: What are plugins used for exactly? Please explain
        plugins.plugins = {list: []};

        // Signal storage
        plugins.signals = $.Callbacks("unique");

        /**
         * List of hooks handlers.
         *
         * A hook is a point of extension. Each time @a Plugins.hook()
         * is called, all the hooks are called with the arguments given and in
         * list order, so that they can process the hook.
         *
         * To insert/delete/list hook handlers, access directly to
         * @a Plugins.hooks.
         *
         * Each hook handler is a function that receives two arguments:
         * - hookname
         * - data
         *
         * A hook handler should return a value interpretable as a false
         * expression if it wants no other hook to process the call, or
         * anything else otherwise.
         *
         * Example hook handler:
         *
         * <code>
         *    var fooHookHandler = function(hookname, data) {
         *      if (hookname === "foo") {
         *         processFoo(data);
         *         return false;
         *      }
         *
         *      return true;
         *    };
         *
         *    // add the handler
         *    Plugins.hooks.push(fooHookHandler);
         * </code>
         */
        plugins.hooks = [];

        /*
         * Adds a plugin.
         *
         * plugin format:
         * {
         *   name: 'test',
         *   directive: 'test', (optional, only if this link has a directive)
         *   head: true | false,
         *   link: ui-sref link,
         *   menu: html() | {icon: icon, text: text}
         * }
         */
        plugins.add = function(plugin) {
            plugins.plugins.list.push(plugin);
        };

        /*
         * Clears the plugins list.
         */
        plugins.clear = function() {
            plugins.plugins.list = [];
        };

        /**
         * Remove a plugin from the list.
         */
        plugins.remove = function(plugin) {
            // Implemented by creating a new list without the plugin of that
            // name
            var pluginList = plugins.plugins.list;
            plugins.plugins.list = [];
            pluginList.forEach(function(pluginFromList) {
                if (plugin.name !== pluginFromList.name) {
                    plugins.plugins.list.push(pluginFromList);
                }
            });
        };

        /**
         * Emits a signal by name.
         *
         * @data can be any object or even null.
         */
        plugins.emit = function(signalName, data) {
            plugins.signals.fire(signalName, data);
        };

        /**
         * Calls to a hook by name.
         *
         * Each function stored as a hook is called with the provided
         * @a hookname and @a data in the hook insertion order. When a hook
         * returns a value interpretable as false, no more hooks are called.
         *
         * @a data can be any object or even null.
         * @a hookname should be a string.
         *
         * @returns false if any of the hooks returns false, or true otherwise.
         */
        plugins.hook = function(hookname, data) {
            for (var i=0; i<plugins.hooks.length; i++) {
                var h = plugins.hooks[i];
                var ret = h(hookname, data);
                if (!ret) {
                    return false;
                }
            }
            return true;
        };

        return plugins;
    });

/**
 * Directive to include angular templates with directives from plugins into
 * the admin interface
 * This directive is based on the stackoverflow thread:
 * http://stackoverflow.com/questions/17417607/angular-ng-bind-html-unsafe-and-directive-within-it
 **/
angular.module('avRegistration')
.directive(
  'sequentPluginHtml',
  ["$compile", "$sce", "$parse", function ($compile, $sce, $parse)
  {
    return function(scope, element, attrs)
    {
      var parsedHtml = $parse(attrs.ngBindHtml);

      // compile again on template modification
      scope.$watch(
        function()
        {
          return (parsedHtml(scope) || "").toString();
        },
        function()
        {
          // -9999 skips directives in order to prevent recompiling
          // recursively
          $compile(element, null, -9999)(scope);
        }
      );
    };
  }]
);

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

/*
 * The avUi module contains a series of user interface directives and utilities.
 */

angular.module('avUi', []);

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

jQuery.fn.flash = function(duration) {
  var selector = this;

  if (!angular.isNumber(duration)) {
    duration = 300;
  }

  if (selector.attr("is-flashing") === "true") {
    return;
  }

  selector.attr("is-flashing", "true");

  selector
    .addClass("flashing")
    .delay(duration)
    .queue(function() {
      selector.removeClass("flashing").addClass("flashing-out").dequeue();
    })
    .delay(duration)
    .queue(function() {
      selector.removeClass("flashing flashing-out").dequeue();
      selector.attr("is-flashing", "false");
    });
};
/**
 * This file is part of admin-console.
 * Copyright (C) 2020  Sequent Tech Inc <legal@sequentech.io>

 * admin-console is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * admin-console  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with admin-console.  If not, see <http://www.gnu.org/licenses/>.
**/

angular.module('avUi')
  .directive(
    'avChildrenElections', 
    ["ConfigService", function(ConfigService) 
    {
      // we use it as something similar to a controller here
      function link(scope, element, attrs) 
      {
        scope.electionsById = {};
        scope.selectedElectionId = scope.parentElectionId;
        scope.hideParent = (attrs.hideParent === 'true');

        // process each election
        _.each(
          scope.childrenElectionInfo.presentation.categories,
          function (category) 
          {
            category.hidden = true;
            _.each(
              category.events,
              function (election) 
              {
                if (
                  scope.mode === 'checkbox' ||
                  scope.mode === 'toggle-and-callback'
                ) 
                {
                  election.data = election.data || false;
                  election.disabled = election.disabled || false;
                  election.hidden = election.hidden || false;
                  if (!election.hidden) {
                    category.hidden = false;
                  }
                }
              }
            );
          }
        );

        // add a processElection function
        scope.click = function (election) 
        {
          console.log("click to election.event_id = " + election.event_id);
          if (election.disabled) {
            console.log("election disabled, so ignoring click");
            return;
          }
          if (scope.mode === 'checkbox') 
          {
            election.data = !election.data;
          } 
          else if (scope.mode === 'toggle-and-callback')
          {
            scope.selectedElectionId = election.event_id;
            scope.callback({electionId: election.event_id});
          }
        };
      }

      return {
        restrict: 'AE',
        scope:  {
          mode: '@',
          callback: '&?',
          parentElectionId: '@?',
          childrenElectionInfo: '='
        },
        link: link,
        templateUrl: 'avUi/children-elections-directive/children-elections-directive.html'
      };
    }]
  );

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

/*
 * Simple error directive.
 */
angular.module('avUi')
  .directive('avSimpleError', ["$resource", "$window", function($resource, $window) {
    function link(scope, element, attrs) {
      // moves the title on top of the busy indicator
      scope.updateTitle = function() {
        var title = element.find(".av-simple-error-title");

        // set margin-top
        var marginTop = - title.height() - 45;
        var marginLeft = - title.width()/2;
        title.attr("style", "margin-top: " + marginTop + "px; margin-left: " + marginLeft + "px");
      };

      scope.$watch(attrs.title,
        function() {
          scope.updateTitle();
        }
      );
    }
    return {
      restrict: 'AE',
      scope: {},
      link: link,
      transclude: true,
      templateUrl: 'avUi/simple-error-directive/simple-error-directive.html'
    };
  }]);

/**
 * This file is part of voting-booth.
 * Copyright (C) 2021 Sequent Tech Inc <legal@sequentech.io>

 * voting-booth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * voting-booth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with voting-booth.  If not, see <http://www.gnu.org/licenses/>.
**/

angular.module('avUi')
  .controller('ConfirmModal',
    ["$scope", "$modalInstance", "data", function($scope, $modalInstance, data) {
      $scope.data = data;

      $scope.ok = function () {
        $modalInstance.close(data.closingData);
      };

      $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
      };
    }]);

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

angular
  .module('avUi')
  .service(
    'ShowVersionsModalService',
    ["ConfigService", "$modal", "$sce", "$window", function(ConfigService, $modal, $sce, $window) {
      return function () {
        $modal
        .open({
          templateUrl: "avUi/confirm-modal-controller/confirm-modal-controller.html",
          controller: "ConfirmModal",
          size: 'lg',
          resolve: {
            data: function () {
              var mainVersion = $window.i18next.t('avCommon.showVersionModal.mainVersion');
              var versionList = (
                "<li><strong>" + mainVersion + " (deployment-tool):</strong> " +
                ConfigService.mainVersion +
                "<br><br></li>"
              );
              _.each(
                ConfigService.repoVersions,
                function (repo) {
                  versionList += (
                    "<li><strong>" +
                    repo.repoName +
                    ":</strong> " +
                    repo.repoVersion +
                    "</li>"
                  );
                }
              );
              var body = $sce.trustAsHtml($window.i18next.t(
                'avCommon.showVersionModal.body',
                {
                  versionList: versionList,
                  interpolation: { escapeValue: false }
                }
              ));
              return {
                i18n: {
                  header: $window.i18next.t('avCommon.showVersionModal.header'),
                  body: body,
                  confirmButton: $window.i18next.t('avCommon.showVersionModal.confirmButton'),
                },
                hideCancelButton: true
              };
            }
          }
        });
      };
    }]);
  
/**
 * This file is part of common-ui.
 * Copyright (C) 2022 Eduardo Robles <edu@sequentech.io>

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

/**
 * Overrides i18next translations. Example:
 * 
 * ```javascript
 * var override = {"en": {"avBooth.castTheBallot": "Cast thy ballot"}};
 * I18nOverride(override);
 * ```
 * 
 * It has two optional parameters:
 *
 * - overrides: dictionary with the overrides (see example above). If it's empty
 *   it will just use the overrides saved in $window.i18nOverride.
 *
 * - force: false by default. This means that overrides will not be applied if
 *   the provided overrides are the same as before (i.e. same as 
 *   $window.i18nOverride).
 */
angular
  .module('avUi')
  .service(
    'I18nOverride',
    ["$i18next", "$rootScope", "$window", function($i18next, $rootScope, $window)
    {
      return function (overrides, force, languagesConf)
      {
        force = angular.isDefined(force) ? force : false;
        var performOverrides = false;
        if (overrides !== null) {
          performOverrides = (
            force ||
            JSON.stringify(overrides) !== JSON.stringify($window.i18nOverride)
            );
          if (performOverrides) {
            $window.i18nOverride = overrides;
          }
        }

        if (languagesConf)
        {
          $i18next.options.lng = (languagesConf.force_default_language) ?
            languagesConf.default_language : $window.i18next.resolvedLanguage;

          $i18next.options.lngWhitelist = languagesConf.available_languages;
          $i18next.options.preload = languagesConf.available_languages;
        }
        console.log("calling $window.i18next.reloadResources()..");
        $window.i18next
          .reloadResources($i18next.options.preload, ['override'])
          .then(function () {
            if (
              languagesConf &&
              languagesConf.force_default_language &&
              $window.i18next.changeAppLang
            ) {
              console.log("reloadResources: successful. force-changing default lang to=" + languagesConf.default_language);
              $window.i18next.changeAppLang(languagesConf.default_language);
            } else {
              console.log("reloadResources: successful. broadcast i18nextLanguageChange signal");
              $rootScope.$broadcast('i18nextLanguageChange', $i18next.options.lng);
            }
          });
      };
    }]
  );

/**
 * This file is part of common-ui.
 * Copyright (C) 2015-2022  Sequent Tech Inc <legal@sequentech.io>

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

/*
 * Simple change lang directive, that can be used in the navbar as a list
 * element:
 * <li class="dropdown" av-change-lang></li>
 */
angular.module('avUi')
  .directive('avChangeLang', ["$i18next", "ipCookie", "angularLoad", "amMoment", "$rootScope", "ConfigService", "$window", "Authmethod", function(
    $i18next,
    ipCookie,
    angularLoad,
    amMoment,
    $rootScope,
    ConfigService,
    $window,
    Authmethod
  ) {
    function link(scope, element, attrs)
    {    
      scope.deflang = $window.i18next.resolvedLanguage;
      angular.element('#ng-app').attr('lang', scope.deflang);
      scope.langs =  $window.i18next.options.lngWhitelist;
      var isAdmin = Authmethod.isAdmin();
      function triggerDropdown()
      {
        setTimeout(function () {
          angular.element("#lang-dropdown-toggle").click();
        }, 0);
      }
      element.on('click', triggerDropdown);

      // detect language changes
      $rootScope.$on(
        'i18nextLanguageChange',
        function (event, languageCode)
        {
          scope.deflang = languageCode;
          scope.langs = $i18next.options.lngWhitelist;
          scope.$apply();
        }
      );

      // Changes i18n to a specific language, setting also a cookie for
      // remembering it, and updating all the translations instantly.
      //
      // Triggered when the user clicks and selects a language.
      $window.i18next.changeAppLang = scope.changeLang = function(lang)
      {
        $window.i18next
          .changeLanguage(lang)
          .then(function () {
            console.log("changeLang: broadcast i18nextLanguageChange");
            $rootScope.$broadcast('i18nextLanguageChange', $window.i18next.resolvedLanguage);

          });

        console.log("setting cookie");
        var cookieConf = {
          expires: 360,
          path: "/"
        };
        ipCookie(
          "lang",
          lang,
          _.extend(cookieConf, ConfigService.i18nextCookieOptions)
        );
        scope.deflang = lang;
        angular.element('#ng-app').attr('lang', scope.deflang);

        // async load moment i18n
        if (isAdmin) {
          angularLoad
            .loadScript(ConfigService.base + '/locales/moment/' + lang + '.js')
            .then(function () {
              amMoment.changeLocale(lang);
            });
        }
      };
    }

    return {
      restrict: 'AE',
      scope: {},
      link: link,
      templateUrl: 'avUi/change-lang-directive/change-lang-directive.html'
    };
  }]);

/**
 * This file is part of common-ui.
 * Copyright (C) 2023 Sequent Tech Inc <legal@sequentech.io>

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

/*
 * Directive that shows the booth header.
 */
angular
  .module('avUi')
  .directive(
    'avbCommonFooter',
    ["ConfigService", function(ConfigService)
    {
      var link = function(scope, _element, _attrs) {
        scope.configService = ConfigService;
      };
      return {
        restrict: 'AE',
        scope:  {
          float: '='
        },
        link: link,
        templateUrl: 'avUi/common-footer-directive/common-footer-directive.html'
      };
    }]
  );
/**
 * This file is part of common-ui.
 * Copyright (C) 2015-2023 Sequent Tech Inc <legal@sequentech.io>

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

/*
 * Directive that shows the booth header.
 */
angular
  .module('avUi')
  .directive(
    'avbCommonHeader',
    ["ConfigService", "ShowVersionsModalService", function(ConfigService, ShowVersionsModalService)
    {
      var link = function(scope, _element, attrs) {
        scope.parentElection = scope.$parent.parentElection;
        scope.election = scope.$parent.election;
        scope.confirmLogoutModal = scope.$parent.confirmLogoutModal;
        scope.configService = ConfigService;
        scope.ballotHash = attrs.ballotHash !== 'false' && attrs.ballotHash  || false;
        scope.isElectionPortal = ("true" === attrs.isElectionPortal) || false;
        scope.buttonsInfo = attrs.buttonsInfo && JSON.parse(attrs.buttonsInfo) || false;
        scope.defaultLogo = "/booth/img/Sequent_logo.svg";
        scope.enableLogOut = function () {
          var election = (
            (!!scope.parentElection) ?
            scope.parentElection :
            scope.election
          );
  
          return (
            !election ||
            !election.presentation ||
            !election.presentation.extra_options ||
            !election.presentation.extra_options.booth_log_out__disable
          );
        };

        scope.showVersionsModal = ShowVersionsModalService;

        function calculateCountdownPercent() {
          var ratio = (scope.logoutTimeMs - Date.now())/(scope.logoutTimeMs - scope.countdownStartTimeMs);
          return Math.min(100, Math.round(10000*ratio)/100) + '%';
        }

        // find progress bar and update its width
        function updateProgressBar(percent) {
          var element = $(".logout-bar")[0];
          if (!element) {
            // There's no logout on the login page
            return;
          }
          element.style.setProperty('width', percent);
        }

        // helper function for enableLogoutCountdown()
        function updateTimedown() {
          if (scope.$parent.getSessionEndTime) {
            scope.logoutTimeMs = scope.$parent.getSessionEndTime();
          }

          if (scope.$parent.getSessionStartTime) {
            scope.countdownStartTimeMs = scope.$parent.getSessionStartTime(true);
          }

          scope.showCountdown = true;
          var now = Date.now();
          scope.countdownSecs = Math.round((scope.logoutTimeMs - now) / 1000);
          scope.countdownMins = Math.round((scope.logoutTimeMs - now) / (60 * 1000));
          scope.countdownPercent = calculateCountdownPercent();
          updateProgressBar(scope.countdownPercent);
          scope.$apply();
          if (scope.countdownSecs <= 1) {
            return;
          }
          setTimeout(
            updateTimedown,
            1000
          );
        }
      
        // Show countdown on logout button based on cookies
        function enableLogoutCountdown() {
          scope.showCountdown = false;

          if (scope.$parent.isStateCompatibleWithCountdown && !scope.$parent.isStateCompatibleWithCountdown()) {
            return;
          }
  
          var election = (
            (!!scope.parentElection) ?
            scope.parentElection :
            scope.election
          );
  
          if (
            ConfigService.authTokenExpirationSeconds &&
            (
              election &&
              election.presentation &&
              _.isNumber(election.presentation.booth_log_out__countdown_seconds)
            )
          ) {
            scope.showCountdown = false;
            scope.countdownSecs = 0;
            scope.countdownMins = 0;

            var initialTimeMs = scope.$parent.getSessionStartTime && scope.$parent.getSessionStartTime(true) || Date.now();
            scope.elapsedCountdownMs = (
              election.presentation.booth_log_out__countdown_seconds > 0?
              election.presentation.booth_log_out__countdown_seconds :
              ConfigService.authTokenExpirationSeconds
            ) * 1000;
            if (scope.$parent.getSessionEndTime) {
              scope.logoutTimeMs = scope.$parent.getSessionEndTime();
            } else {
              scope.logoutTimeMs = initialTimeMs + ConfigService.authTokenExpirationSeconds * 1000;
            }
            scope.countdownStartTimeMs = scope.logoutTimeMs - scope.elapsedCountdownMs;
            scope.countdownPercent = calculateCountdownPercent();
            updateProgressBar(scope.countdownPercent);

            // If we're on a demo/live preview, the bar is fixed at 100%
            if (scope.isDemo || scope.isPreview) {
              return;
            }
            
            setTimeout(
              updateTimedown,
              election.presentation.booth_log_out__countdown_seconds > 0?  scope.countdownStartTimeMs - Date.now() : 0
            );

          }
        }
        setTimeout(enableLogoutCountdown, 0);
      };
      return {
        restrict: 'AE',
        scope: {
          hashHelp: '&'
        },
        link: link,
        templateUrl: 'avUi/common-header-directive/common-header-directive.html'
      };
    }]
  );
/**
 * This file is part of common-ui.
 * Copyright (C) 2015-2023  Sequent Tech Inc <legal@sequentech.io>

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

/*
 * directive used to position an element always at the bottom, so that it's
 * always shown completely. There are two scenarios:
 * a) if the page has no scroll, we assume the element is shown, and do nothing
 * b) if the page has scroll, the bottom of the page is not completely (or at
 *    all) being shown, so we set the affixed element the class affix-bottom and
 *    make space for it giving some bottom margin in its parent element.
 *
 * As an optional trigger to the settings of the affix-bottom, you can also set
 * the data-force-affix-width attribute in the affixed element to a number of
 * pixels. If this attribute is set and the window width is less than this,
 * automatically the element will be affixed.
 */
angular.module('avUi')
  .directive('avAffixBottom', ["$window", "$timeout", "$parse", function($window, $timeout, $parse) {
    var affixBottomClass = "affix-bottom";
    var checkPosition = function(scope, instance, el, options) {

      var affix = false;
      var elHeight = $(el).actual('height');

      if (($("body").height() + elHeight > window.innerHeight) ||
          (instance.forceAffixWidth && window.innerWidth < instance.forceAffixWidth) ||
          !instance.forceAffixWidth || instance.forceAffix) {
        affix = affixBottomClass;
      }

      if (instance.affixed === affix) {
        return;
      }

      instance.affix = affix;
      instance.setIsAffix(scope, affix);
      el.removeClass("hidden");

      if (!affix) {
        el.removeClass(affixBottomClass);
        $(el).parent().css("margin-bottom", instance.defaultBottomMargin);
      } else {
        el.addClass(affixBottomClass);

        // add bottom-margin automatically
        $(el).parent().css("margin-bottom", elHeight + "px");
      }

    };

    return {
      restrict: 'EAC',
      link: function(scope, iElement, iAttrs) {
        // instance saves state between calls to checkPosition
        var instance = {
          affix: false,
          getIsAffix: null,
          setIsAffix: angular.noop,
          defaultBottomMargin: iElement.css("margin-bottom"),
          forceAffixWidth: parseInt(iAttrs.forceAffixWidth, 10),
          forceAffix: iAttrs.forceAffix === "true"
        };


        if (iAttrs.avAffixBottom.length > 0) {
          instance.getIsAffix = $parse(iAttrs.avAffixBottom);
          instance.setIsAffix = instance.getIsAffix.assign;
        }

        // timeout is used with callCheckPos so that we do not create too many
        // calls to checkPosition, at most one per 300ms
        var timeout;

        function callCheckPos() {
          timeout = $timeout(function() {
            $timeout.cancel(timeout);
            checkPosition(scope, instance, iElement, iAttrs);
          }, 300);
        }
        callCheckPos();

        // watch for window resizes and element resizes too
        angular.element($window).on('resize', callCheckPos);
        angular.element(document.body).on('resize', callCheckPos);
        console.log("iElement NOT resize, height = " + iElement.height());
        angular.element(iElement).on('resize', callCheckPos);
      }
    };

  }]);

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

/**
 * Usage:
 *
 * <div>
 *    <div>I need some space, this is a sibling</div>
 *    <div av-auto-height>
 *        I stretch to the available height,
 *        calculated from the height available from .parent and my siblings.
 *    </div>
 * </div>
 */
angular.module('avUi')
  .directive('avAutoHeight', ["$window", "$timeout", function($window, $timeout) {
    return {
      link: function(scope, element, attrs) {
        var sibling, recalculate, promise = null;

        sibling = function() {
          return element.closest(attrs.parentSelector).find(attrs.siblingSelector);
        };

        recalculate = function () {
          if (promise) {
            $timeout.cancel(promise);
          }
          promise = $timeout(function() {
            var additionalHeight = 0, height;
            if (!!attrs.additionalHeight) {
              additionalHeight = parseInt(attrs.additionalHeight, 10);
            }
            height = sibling().height();
            element.css('max-height', (height + additionalHeight) + "px");
          }, 300);
        };

        scope.$watch(
          function () {
            return sibling().height();
          },
          function (newValue, oldValue) {
            recalculate();
          });

        recalculate();
      }
    };
  }]
);
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

angular.module('avUi')
  .directive('avAffixTopOffset', ["$window", "$timeout", "$parse", function($window, $timeout, $parse) {
    var affixClass = "affix-top";
    var checkPosition = function(scope, instance, el, options) {

      var affix = false;
      var offset = el.offset();

      if (instance.affix && $window.pageYOffset + 20 >= instance.scrollAffix) {
        return;
      } else if (offset.top - $window.pageYOffset < instance.avAffixTopOffset) {
        affix = true;
      }

      if (instance.affix === affix) {
        return;
      }

      instance.affix = affix;
      instance.scrollAffix = $window.pageYOffset;
      if (!affix) {
        el.removeClass(affixClass);
        el.attr("style", "");

        if (options.affixPlaceholder !== undefined) {
          $(options.affixPlaceholder).removeClass("affixed");
        }
      } else {
        el.addClass(affixClass);
        el.data("page-offset", $window.pageYOffset);
        el.css("position", "fixed");
        el.css("float", "none");
        el.css("top", Math.floor(instance.avAffixTopOffset) + "px");
        el.css("left", Math.floor(instance.baseOffset.left) + "px");
        el.css("width", Math.floor(instance.baseWidth) + "px");
        el.css( "z-index", "10");

        if (options.affixPlaceholder !== undefined) {
          $(options.affixPlaceholder).addClass("affixed");
        }
      }

    };

    return {
      restrict: 'EAC',
      link: function(scope, iElement, iAttrs) {
        // instance saves state between calls to checkPosition
        var instance = {
          affix: false,
          scrollAffix: null,
          baseOffset: iElement.offset(),
          baseWidth: iElement.width(),
          avAffixTopOffset: parseInt(iAttrs.avAffixTopOffset, 10)
        };


        function callCheckPos() {
          checkPosition(scope, instance, iElement, iAttrs);
        }
        callCheckPos();

        // when window resizes, the baseoffset etc needs to be reset
        function resize() {
          iElement.removeClass(affixClass);
          iElement.attr("style", "");
          instance.affix = false;
          instance.scrollAffix = null;
          $timeout(function () {
            instance.baseOffset = iElement.offset();
            instance.baseWidth = iElement.width();
            callCheckPos();
          }, 300);
        }

        // watch for window scrolling
        angular.element($window).on('scroll', callCheckPos);
        angular.element($window).on('resize', resize);
      }
    };

  }]);

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

/*
 * directive used to position an element always at the top. It just sets its
 * specified element with a margin-top to make space for the affixed element.
 * This is done dynamically, so that each time the affixed element's height
 * changes, the top-margin of the specified is recalculated and set.
 */
angular.module('avUi')
  .directive('avAffixTop', ["$window", "$timeout", function($window, $timeout) {

    // add margin-top automatically
    var updateMargin = function(el, options) {
      var minHeight = parseInt(options.minHeight);
      var height = Math.max(
        $(el).height(),
        (angular.isNumber(minHeight) && !isNaN(minHeight) ? minHeight : 0) );
      $(options.avAffixTop).css("padding-top", height + "px");
    };

    return {
      restrict: 'EAC',
      link: function(scope, iElement, iAttrs) {
        updateMargin(iElement, iAttrs);

        if (iAttrs.minHeight === undefined) {
          iAttrs.minHeight = "20";
        }

        // timeout is used with callCheckPos so that we do not create too many
        // calls to checkPosition, at most one per 300ms
        var timeout;

        function updateMarginTimeout() {
          timeout = $timeout(function() {
            $timeout.cancel(timeout);
            updateMargin(iElement, iAttrs);
          }, 300);
        }
        updateMarginTimeout();

        // watch for window resizes and element resizes too
        angular.element(iElement).bind('resize', updateMarginTimeout);
        angular.element($window).bind('resize', updateMarginTimeout);
        $(iAttrs.avAffixTop).change(updateMarginTimeout);
      }
    };

  }]);

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

/*
 * avCollapsing limits the default maximum height of an element by making it
 * collapsable if it exceeds the max-height of the selector.
 *  - if the element's height doesn't exceed its maximum height, the
 *    data-toggle-selector element will be set to hidden
 *  - if the element's height exceeds its maximum height, the
 *    data-toggle-selector element will be removed the class "hidden".
 *  - if the data-toggle-selector element it contains is clicked, they will be
 *    added the class ".in".
 *  - if the element's height exceeds its max height and the toggle is not
 *    ".in", then it adds the ".collapsed" class to the element, and makes sure
 *    the data-toggle-selector element is not hidden.
 *  - it will watch the element and window resizes to see if the conditions
 *    change.
 * - both maxHeightSelector and data-toggle-selector will be found using the
 *   parent selector as a base if the attribute "parent-selector" is set.
 *   Otherwise, it will directly a global angular.element() to find them.
 */
angular.module('avUi')
  .directive('avCollapsing', ["$window", "$timeout", function($window, $timeout) {

    function select(instance, el, selector) {
      var val;
      if (!!instance.parentSelector) {
        val = el.closest(instance.parentSelector).find(selector);
      } else {
        val = angular.element(selector);
      }
      return val;
    }

    function collapseEl(instance, el) {
      var val = null;
      if (!!instance.collapseSelector) {
        val = select(instance, el, instance.collapseSelector);
      } else {
        val = angular.element(el);
      }
      return val;
    }

    var checkCollapse = function(instance, el, options) {
      var maxHeight = select(instance, el, instance.maxHeightSelector).css("max-height");
      if (_.isUndefined(maxHeight)) {
        console.log("max-height selector not found");
        return;
      }
      var height = angular.element(el)[0].scrollHeight;

      // we want to remove padding-top in the calculation
      var paddingTop = angular.element(el).css('padding-top');

      if (maxHeight.indexOf("px") === -1) {
        console.log("invalid non-pixels max-height for " + instance.maxHeightSelector);
        return;
      }

      if (!paddingTop || paddingTop.indexOf("px") === -1) {
        paddingTop = 0;
      } else {
        paddingTop = parseInt(paddingTop.replace("px", ""));
      }

      maxHeight = parseInt(maxHeight.replace("px", ""));

      // make sure it's collapsed if it should
      if (height - paddingTop > maxHeight) {
        // already collapsed
        if (instance.isCollapsed) {
          return;
        }
        instance.isCollapsed = true;
        collapseEl(instance, el).addClass("collapsed");
        select(instance, el, instance.toggleSelector).removeClass("hidden in");

      // removed collapsed and hide toggle otherwise
      } else {
        // already not collapsed
        if (!instance.isCollapsed) {
          return;
        }
        instance.isCollapsed = false;
        collapseEl(instance, el).removeClass("collapsed");
        select(instance, el, instance.toggleSelector).addClass("hidden");
      }
    };

    var toggleCollapse = function(instance, el, options) {
      // if it's collapsed, uncollapse
      if (instance.isCollapsed) {
        collapseEl(instance, el).removeClass("collapsed");
        select(instance, el, instance.toggleSelector).addClass("in");

      // collapse otherwise
      } else {
        collapseEl(instance, el).addClass("collapsed");
        select(instance, el, instance.toggleSelector).removeClass("in");
      }


      instance.isCollapsed = !instance.isCollapsed;
    };

    return {
      restrict: 'EAC',
      link: function(scope, iElement, iAttrs) {
        var instance = {
          isCollapsed: false,
          maxHeightSelector: iAttrs.avCollapsing,
          toggleSelector: iAttrs.toggleSelector,
          parentSelector: iAttrs.parentSelector,
          collapseSelector: iAttrs.collapseSelector
        };

        // timeout is used with callCheck so that we do not create too many
        // calls to checkPosition, at most one per 100ms
        var timeout;

        function callCheck() {
          timeout = $timeout(function() {
            $timeout.cancel(timeout);
            checkCollapse(instance, iElement, iAttrs);
          }, 500);
        }
        callCheck();


        function launchToggle() {
            toggleCollapse(instance, iElement, iAttrs);
        }

        // watch for window resizes and element resizes too
        angular.element($window).bind('resize', callCheck);
        angular.element(iElement).bind('resize', callCheck);

        // watch toggle's clicking
        angular.element(instance.toggleSelector).bind('click', launchToggle);
      }
    };

  }]);

/*
The MIT License (MIT)
Copyright (c) 2014 Kent C. Dodds
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Source: https://github.com/kentcdodds/kcd-angular
Copyright (c) 2014 Kent C. Dodds kent+github@doddsfamily.us
 */

angular.module('avUi').directive('avRecompile', ["$compile", "$parse", function($compile, $parse) {
  'use strict';
  function getElementAsHtml(el) {
    return angular.element('<a></a>').append(el.clone()).html();
  }

  return {
    scope: true, // required to be able to clear watchers safely
    compile: function(el) {
      var template = getElementAsHtml(el);
      return function link(scope, $el, attrs) {
        var stopWatching = scope.$parent.$watch(attrs.avRecompile, function(_new, _old) {
          var useBoolean = attrs.hasOwnProperty('useBoolean');
          if ((useBoolean && (!_new || _new === 'false')) || (!useBoolean && (!_new || _new === _old))) {
            return;
          }
          // reset kcdRecompile to false if we're using a boolean
          if (useBoolean) {
            $parse(attrs.kcdRecompile).assign(scope.$parent, false);
          }

          // recompile
          var newEl = $compile(template)(scope.$parent);
          $el.replaceWith(newEl);

          // Destroy old scope, reassign new scope.
          stopWatching();
          scope.$destroy();
        });
      };
    }
  };
}]);

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

// source: https://gist.github.com/tommaitland/7579618#file-ng-debounce-js
angular.module('avUi')
  .directive('avDebounce', ["$timeout", function($timeout) {
    return {
      restrict: 'A',
      require: 'ngModel',
      priority: 99,
      link: function(scope, elm, attr, ngModelCtrl) {
        if (attr.type === 'radio' || attr.type === 'checkbox') {
          return;
        }
        elm.unbind('input');
        var debounce;

        elm.bind('input', function() {
          $timeout.cancel(debounce);
          debounce = $timeout( function() {
            scope.$apply(function() {
              ngModelCtrl.$setViewValue(elm.val());
            });
          }, attr.avDebounce || 500);
        });

        elm.bind('blur', function() {
          scope.$apply(function() {
            ngModelCtrl.$setViewValue(elm.val());
          });
        });
      }
    };
}]);
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

angular.module('avUi')
  .service('InsideIframeService', function() {
    return function() {
      try {
          return window.self !== window.top;
      } catch (e) {
          return true;
      }
    };
  });

/**
 * This file is part of admin-console.
 * Copyright (C) 2015-2021  Sequent Tech Inc <legal@sequentech.io>

 * admin-console is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * admin-console  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with admin-console.  If not, see <http://www.gnu.org/licenses/>.
**/

angular
  .module('avUi')
  .directive(
    'avLoadCss', 
    function() 
    {
      function link(scope, element, _attrs) 
      {
        function updateCss(newValue, oldValue)
        {
          if (newValue && typeof newValue === 'string' && newValue !== oldValue) 
          {
            element.text(newValue);
          }
        }
        updateCss(scope.css);
        scope.$watch("css", updateCss);
      }

      return {
        restrict: 'AE',
        scope: {
          css: '='
        },
        link: link
      };
  });

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

/*
 * Returns the percentage of votes received by an answer. The base number
 * of the percentage that is used depends on the
 * "answer_total_votes_percentage" option in the question.
 */
angular.module('avUi')
  .service('PercentVotesService', function() {
    return function (total_votes, question, over, format) {
      if (format === undefined) {
        format = "str";
      }
      
      function print(num) {
        if (format === "str") {
          return num.toFixed(2) + "%";
        } else {
          return num;
        }
      }

      // special case
      if (total_votes === 0) {
        return print(0.00);
      }

      var base = question.totals.valid_votes + question.totals.null_votes + question.totals.blank_votes;
      if (over === undefined || over === null) {
        over = question.answer_total_votes_percentage;
      }
      if ("over-valid-votes" === over || "over-total-valid-votes" === over) {
        base = question.totals.valid_votes;
      }
      else if ("over-total-valid-points" === over &&
        undefined !== question.totals.valid_points) {
        base = question.totals.valid_points;
      }

      return print(100*total_votes / base);
    };
  });

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

/*
 * Checks input data with a list of checks.
 *
 * Example:
 *
        var checks = [
          {
            check: "array-group",
            prefix: "question-",
            checks: [
              {check: "is-array", key: "questions"},
              {check: "array-length", key: "questions", min: 1, max: 40},
              {
                check: "array-key-group-chain",
                key: "questions",
                prefix: "question-",
                checks: [
                  {check: "is-int", key: "min"},
                  {check: "is-int", key: "max"},
                  {check: "is-int", key: "num_winners"},
                  {check: "is-array", key: "answers"},
                  {check: "array-length", key: "answers", min: 1, max: 10000},
                  {check: "int-size", key: "min", min: 0, max: "$value.max"},
                  {
                    check: "int-size",
                    key: "max",
                    min: "$value.min",
                    max: "$value.answers.length"
                  },
                  {
                    check: "int-size",
                    key: "num_winners",
                    max: "$value.answers.length"
                  }
                ]
              }
            ]
          }
        ];

        scope.errors = [];
        CheckerService({
          checks: checks,
          data: scope.elections,
          onError: function (errorKey, errorData) {
            scope.errors.push({
              data: errorData,
              key: errorKey
            });
          }
        });
 */
angular.module('avUi')
  .service('CheckerService', ["$filter", function($filter) {
    function checker(d) {

      /*
       * Used to eval the expressions given by the programmer in the checker
       * script
       */
      function evalValue(code, $value) {
        if (angular.isString(code)) {
          /* jshint ignore:start */
          return eval(code);
          /* jshint ignore:end */
        } else {
          return code;
        }
      }

      function sumStrs(str1, str2) {
        var ret = "";
        if (angular.isString(str1)) {
          ret = str1;
        }
        if (angular.isString(str2)) {
          ret += str2;
        }
        return ret;
      }

      function error(errorKey, errorData, postfix) {
        angular.extend(errorData, d.errorData);
        d.onError(
          _.reduce([d.prefix, errorKey, postfix], sumStrs, ""),
          errorData
        );
      }

      if (angular.isUndefined(d.errorData)) {
        d.errorData = {};
      }

      var ret = _.every(d.checks, function (item) {
        var pass = true;
        var itemMin;
        var itemMax;
        var max;
        var min;
        var dataToCheck = angular.isDefined(item.key) ? d.data[item.key] : d.data;
        if (item.check === "is-int") {
          pass = angular.isNumber(dataToCheck, item.postfix);
          if (!pass) {
            error(item.check, {key: item.key}, item.postfix);
          }

        } else if (item.check === "is-array") {
          pass = angular.isArray(dataToCheck, item.postfix);
          if (!pass) {
            error(item.check, {key: item.key}, item.postfix);
          }
        } else if (item.check === "lambda") {
          if (!item.validator(dataToCheck)) {
            var errorData = {key: item.key};
            if (!angular.isUndefined(item.appendOnErrorLambda)) {
              errorData = item.appendOnErrorLambda(dataToCheck);
            }
            if (_.isObject(item.append) &&
                _.isString(item.append.key) &&
                !_.isUndefined(item.append.value)) {
              errorData[item.append.key] = evalValue(item.append.value, item);
            }
            error(item.check, errorData, item.postfix);
          }

        } else if (item.check === "is-string-if-defined") {
          pass = angular.isUndefined(dataToCheck) ||
                   angular.isString(dataToCheck, item.postfix);
          if (!pass) {
            error(item.check, {key: item.key}, item.postfix);
          }

        } else if (item.check === "array-length-if-defined") {
          if (angular.isDefined(dataToCheck)) {
            itemMin = evalValue(item.min, d.data);
            itemMax = evalValue(item.max, d.data);

            if (angular.isArray(dataToCheck) || angular.isString(dataToCheck))
            {
              min = angular.isUndefined(item.min) || dataToCheck.length >= itemMin;
              max = angular.isUndefined(item.max) || dataToCheck.length <= itemMax;
              pass = min && max;
              if (!min) {
                error(
                  "array-length-min",
                  {key: item.key, min: itemMin, num: dataToCheck.length},
                  item.postfix);
              }
              if (!max) {
                var itemErrorData0 = {key: item.key, max: itemMax, num: dataToCheck.length};
                error(
                  "array-length-max",
                  itemErrorData0,
                  item.postfix);
              }
            }
          }
        } else if (item.check === "is-string") {
          pass = angular.isString(dataToCheck, item.postfix);
          if (!pass) {
            error(item.check, {key: item.key}, item.postfix);
          }

        } else if (item.check === "array-length") {
          itemMin = evalValue(item.min, d.data);
          itemMax = evalValue(item.max, d.data);

          if (angular.isArray(dataToCheck) || angular.isString(dataToCheck))
          {
            min = angular.isUndefined(item.min) || dataToCheck.length >= itemMin;
            max = angular.isUndefined(item.max) || dataToCheck.length <= itemMax;
            pass = min && max;
            if (!min) {
              error(
                "array-length-min",
                {key: item.key, min: itemMin, num: dataToCheck.length},
                item.postfix);
            }
            if (!max) {
              var itemErrorData = {key: item.key, max: itemMax, num: dataToCheck.length};
              error(
                "array-length-max",
                itemErrorData,
                item.postfix);
            }
          }

        } else if (item.check === "int-size") {
          itemMin = evalValue(item.min, d.data);
          itemMax = evalValue(item.max, d.data);
          min = angular.isUndefined(item.min) || dataToCheck >= itemMin;
          max = angular.isUndefined(item.max) || dataToCheck <= itemMax;
          pass = min && max;
          if (!min) {
            error(
              "int-size-min",
              {key: item.key, min: itemMin, value: dataToCheck},
              item.postfix);
          }
          if (!max) {
            error(
              "int-size-max",
              {key: item.key, max: itemMax, value: dataToCheck},
              item.postfix);
          }
        } else if (item.check === "group-chain") {
          pass = _.all(
            _.map(
              item.checks,
              function(check) {
                return checker({
                  data: d.data,
                  errorData: d.errorData,
                  onError: d.onError,
                  checks: [check],
                  prefix: sumStrs(d.prefix, item.prefix)
                });
              })
            );
        } else if (item.check === "array-key-group-chain") {
          pass = _.every(
            dataToCheck,
            function (data, index) {
              var extra = {};
              var prefix = "";
              if (angular.isString(d.prefix)) {
                prefix = d.prefix;
              }
              if (angular.isString(item.prefix)) {
                prefix += item.prefix;
              }
              extra.prefix = prefix;
              extra[item.append.key] = evalValue(item.append.value, data);
              return checker({
                data: data,
                errorData: angular.extend({}, d.errorData, extra),
                onError: d.onError,
                checks: item.checks,
                prefix: sumStrs(d.prefix, item.prefix),
              });
            });
        } else if (item.check === "array-group-chain") {
          pass = _.every(d.data, function (data, index) {
            var extra = {};
            extra[item.append.key] = evalValue(item.append.value, data);
            return checker({
              data: data,
              errorData: angular.extend({}, d.errorData, extra),
              onError: d.onError,
              checks: item.checks,
              prefix: sumStrs(d.prefix, item.prefix),
            });
          });
        } else if (item.check === "array-group") {
          pass = _.contains(
            _.map(
              d.data,
              function (data, index) {
                var extra = {};
                extra[item.append.key] = evalValue(item.append.value, data);
                return checker({
                  data: data,
                  errorData: angular.extend({}, d.errorData, extra),
                  onError: d.onError,
                  checks: item.checks,
                  prefix: sumStrs(d.prefix, item.prefix),
                });
              }),
            true);
        } else if (item.check === "object-key-chain") {
          pass = _.isString(item.key) && _.isObject(dataToCheck);
          if (!!pass) {
            var data = dataToCheck;
            var extra = {};
            extra[item.append.key] = evalValue(item.append.value, data);
            var prefix = "";
            if (angular.isString(d.prefix)) {
              prefix += d.prefix;
            }
            if (angular.isString(item.prefix)) {
              prefix += item.prefix;
            }
            pass = _.every(
              item.checks,
              function (check, index) {
                return checker({
                  data: data,
                  errorData: angular.extend({}, d.errorData, extra),
                  onError: d.onError,
                  checks: [check],
                  prefix: prefix,
                });
              });
          }
        }
        if (!pass && d.data.groupType === 'chain') {
          return false;
        }
        return true;
      });

      return ret;
    }
    return checker;
  }]);

/**
 * This file is part of common-ui.
 * Copyright (C) 2022  Sequent Tech Inc <legal@sequentech.io>

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


angular.module('avUi')
    .factory('ElectionCreation', function() {
        var service = {
        };

        service.generateAuthapiRequest = function (el) {
            // sanitize some unneeded values that might still be there. This
            // needs to be done because how we use ng-model
            if (el.census.config.subject && !_.contains(['email', 'email-otp'], el.census.auth_method)) {
              delete el.census.config.subject;
            }
            var authAction = el.census.config['authentication-action'];
            if (authAction.mode === 'vote') {
              authAction["mode-config"] = null;
            }

            var d = {
                auth_method: el.census.auth_method,
                oidc_providers: el.census.oidc_providers,
                has_ballot_boxes: el.census.has_ballot_boxes,
                support_otl_enabled: el.census.support_otl_enabled || false,
                census: el.census.census,
                auth_method_config: el.census.config,
                extra_fields: [],
                admin_fields: [],
                num_successful_logins_allowed: el.num_successful_logins_allowed,
                scheduled_events: el.scheduled_events || null,
                allow_public_census_query: el.allow_public_census_query,
                force_census_query: el.force_census_query || false,
                hide_default_login_lookup_field: el.hide_default_login_lookup_field,
                parent_id: el.parent_id || null,
                children_election_info: el.children_election_info || null,
                alternative_auth_methods: el.census.alternative_auth_methods || null
            };

            // Set election id if existing in election configuration
            if (el.id) {
              d.id = el.id;
            }

            d.admin_fields = _.filter(el.census.admin_fields, function(af) {
              return true;
            });

            d.extra_fields = _.filter(el.census.extra_fields, function(ef) {
              delete ef.disabled;
              delete ef.must;
              delete ef.value;

              // only add regex if it's filled and it's a text field
              if (!angular.isUndefined(ef.regex) &&
                (!_.contains(['int', 'text'], ef.type) || $.trim(ef.regex).length === 0)) {
                delete ef.regex;
              }

              if (_.contains(['bool', 'captcha'], ef.type)) {
                delete ef.min;
                delete ef.max;
              } else {
                if (!!ef.min) {
                  ef.min = parseInt(ef.min);
                }
                if (!!ef.max) {
                  ef.max = parseInt(ef.max);
                }
              }
              return true;
            });

            return d;
        };

        service.generateAuthapiResponse = function (el) {
          var election = service.generateAuthapiRequest(el);

          election.users = 0;
          election.tally_status = "notstarted";
          election.allow_public_census_query = false;
          election.created = "2022-12-05T15:22:34.862203%2B00:00";
          election.based_in = election.based_in || null;
          election.hide_default_login_lookup_field = election.hide_default_login_lookup_field || false;
          election.auth_method_config.config = {
            allow_user_resend: election.auth_method_config.allow_user_resend
          };
          election.openid_connect_providers = [];
          election.inside_authenticate_otl_period = false;

          return election;
        };

        service.generateBallotBoxRequest = function (data) {
          var el = angular.copy(data);

          if (typeof el.extra_data === 'object') {
              el.extra_data = JSON.stringify(el.extra_data);
          }
          if (typeof el.tallyPipesConfig === 'object') {
          el.tallyPipesConfig = JSON.stringify(el.tallyPipesConfig);
          }
          if (typeof el.ballotBoxesResultsConfig === 'object') {
          el.ballotBoxesResultsConfig = JSON.stringify(el.ballotBoxesResultsConfig);
          }

          _.each(el.questions, function (q) {
            _.each(q.answers, function (answer) {
              answer.urls = _.filter(answer.urls, function(url) { return $.trim(url.url).length > 0;});
            });
          });

          return el;
        };

        service.generateBallotBoxResponse = function (el) {
          var election = service.generateBallotBoxRequest(el);

          election.ballotBoxesResultsConfig = election.ballotBoxesResultsConfig || "";
          election.virtual = election.virtual || false;
          election.tally_allowed = false;
          election.publicCandidates = true;
          election.virtualSubelections = election.virtualSubelections || [];
          election.logo_url = election.logo_url || "";

          return {
            id: election.id,
            configuration: election,
            state:"started",
            // always use the same public keys
            pks: JSON.stringify(election.questions.map(function (q) {
              return {
                q: '24792774508736884642868649594982829646677044143456685966902090450389126928108831401260556520412635107010557472033959413182721740344201744439332485685961403243832055703485006331622597516714353334475003356107214415133930521931501335636267863542365051534250347372371067531454567272385185891163945756520887249904654258635354225185183883072436706698802915430665330310171817147030511296815138402638418197652072758525915640803066679883309656829521003317945389314422254112846989412579196000319352105328237736727287933765675623872956765501985588170384171812463052893055840132089533980513123557770728491280124996262883108653723',
                p: '49585549017473769285737299189965659293354088286913371933804180900778253856217662802521113040825270214021114944067918826365443480688403488878664971371922806487664111406970012663245195033428706668950006712214428830267861043863002671272535727084730103068500694744742135062909134544770371782327891513041774499809308517270708450370367766144873413397605830861330660620343634294061022593630276805276836395304145517051831281606133359766619313659042006635890778628844508225693978825158392000638704210656475473454575867531351247745913531003971176340768343624926105786111680264179067961026247115541456982560249992525766217307447',
                y: '25233303610624276354982811986201834016697399044876854448496917180808794460600684041443897755355520203095802059616029587815193698920031231714345315925211168639624595654625128533802897292140868582328656520616332091010467955507834092620045939069623671407818190171090021825044623127204061232697474129851550188729946673890631720197446903235998242798036758238763406311552128366413931805575611209227161344639186615808279023879377699069225460149170905910146022296229949546176735955646970920639173343909852697354526383408023054713403757933275765703706664300550788437833505997522376371433614613665995482912523477014539823187236',
                g: '27257469383433468307851821232336029008797963446516266868278476598991619799718416119050669032044861635977216445034054414149795443466616532657735624478207460577590891079795564114912418442396707864995938563067755479563850474870766067031326511471051504594777928264027177308453446787478587442663554203039337902473879502917292403539820877956251471612701203572143972352943753791062696757791667318486190154610777475721752749567975013100844032853600120195534259802017090281900264646220781224136443700521419393245058421718455034330177739612895494553069450438317893406027741045575821283411891535713793639123109933196544017309147'
              };
            })),
            tallyPipesConfig: election.tallyPipesConfig,
            ballotBoxesResultsConfig: election.ballotBoxesResultsConfig,
            virtual: election.virtual,
            tallyAllowed: false,
            publicCandidates:true,
            logo_url: election.logo_url,
            trusteeKeysState: []
          };
        };
        
        return service;
    });

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

/*
 * Given a number, adds dots every three digits.
 *
 * Example:
 *
 *    AddDotsToIntService(1234567) --> "1.234.567"
 *    AddDotsToIntService(1111.234567) --> "1.111,234567"
 */
angular.module('avUi')
  .service('AddDotsToIntService', function() {
    return function (number, fixedDigits) {
      if (angular.isNumber(fixedDigits) && fixedDigits >= 0) {
        number = number.toFixed(parseInt(fixedDigits));
      }
      var number_str = (number + "").replace(".", ",");
      var ret = "";
      var commaPos = number_str.length;
      if (number_str.indexOf(",") !== -1) {
        commaPos = number_str.indexOf(",");
      }
      for (var i = 0; i < commaPos; i++) {
        var reverse = commaPos - i;
        if ((reverse % 3 === 0) && reverse > 0 && i > 0) {
          ret = ret + ".";
        }
        ret = ret + number_str[i];
      }
      return ret + number_str.substr(commaPos, number_str.length);
    };
  });

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

angular.module('avUi')
  .service('EndsWithService', function() {
    return function (originString, searchString) {
        if (!angular.isString(originString) || !angular.isString(searchString)) {
          return false;
        }
        var lastIndex = originString.indexOf(searchString);
        return lastIndex !== -1 && lastIndex === originString.length - searchString.length;
      };
    });
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

/*
 * Save data between states.
 *
 * Example:
 *
 *    StateDataService.go('election.public.show.login', {id: autheventid}, {something: "foo"})
 *    StateDataService.getData() --> {something: "foo"}
 */
angular.module('avUi')
  .service('StateDataService', ["$state", function($state) {
    var data = {};
    return {
      go: function (path, stateData, newData) {
        data = angular.copy(newData);
        $state.go(path, stateData);
      },
      getData: function () {
        return data;
      }
    };
  }]);

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

/**
 * Always scrolls to bottom the div to which the directive is attached when
 * the observed property is modified.
 *
 * Example:
 *
 *    <div av-autoscroll-down ng-bind-html="log"></div>
 */
angular.module('avUi')
  .directive('avScrollToBottom', ["$timeout", function($timeout) {
    return {
      restrict: 'A',
      link: function postLink(scope, element, attrs) {
        scope.$watch(
          function () {
            return element.children().length;
          },
          function () {
            element.animate({ scrollTop: element.prop('scrollHeight') }, 300);
          }
        );
      }
    };
}]);
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

/**
 * Adds target blank to links.
 *
 * Usage example:
 *
 * <div ng-bind-html="foo.contentHtml | addTargetBlank"></div>
 */
angular.module('avUi')
  .filter('addTargetBlank', function(){
    return function(x) {
      //defensively wrap in a div to avoid 'invalid html' exception, then add
      //the target _blank to links
      var tree = angular.element('<div>'+x+'</div>');
      tree.find('a').attr('target', '_blank');

      //trick to have a string representation
      return angular.element('<div>').append(tree).html();
    };
  });
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

angular
  .module('avUi')
  .filter(
    'htmlToText',
    ["$sanitize", function($sanitize)
    {
      return function(text)
      {
        var sanitizedText = $sanitize(text);
        return angular.element('<div>' + sanitizedText + '</div>').text();
      };
    }]
  );
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

// see https://github.com/angular/angular.js/issues/1404
angular.module('avUi')
  .config(["$provide", function($provide) {
    $provide.decorator('ngModelDirective', ["$delegate", function($delegate) {
      var ngModel = $delegate[0], controller = ngModel.controller;
      ngModel.controller = ['$scope', '$element', '$attrs', '$injector', function(scope, element, attrs, $injector) {
        var $interpolate = $injector.get('$interpolate');
        attrs.$set('name', $interpolate(attrs.name || '')(scope));
        $injector.invoke(controller, Object.setPrototypeOf(this, controller.prototype), {
          '$scope': scope,
          '$element': element,
          '$attrs': attrs
        });
      }];
      return $delegate;
    }]);
    $provide.decorator('formDirective', ["$delegate", function($delegate) {
      var form = $delegate[0], controller = form.controller;
      form.controller = ['$scope', '$element', '$attrs', '$injector', function(scope, element, attrs, $injector) {
        var $interpolate = $injector.get('$interpolate');
        attrs.$set('name', $interpolate(attrs.name || attrs.ngForm || '')(scope));
        $injector.invoke(controller, Object.setPrototypeOf(this, controller.prototype), {
          '$scope': scope,
          '$element': element,
          '$attrs': attrs
        });
      }];
      return $delegate;
    }]);
  }]);

 /**
 * This file is part of common-ui.
 * Copyright (C) 2015-2016  Sequent Tech Inc <legal@sequentech.io>

 * election-portal is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * election-portal  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with election-portal.  If not, see <http://www.gnu.org/licenses/>.
**/

/*
 * Shows the public view of an election. Controls mainly the changing inner states
 * loading config, showing results, showing error if needed.
 */
angular.module('avUi').controller('DocumentationUiController',
  ["$state", "$stateParams", "$http", "$scope", "$sce", "$i18next", "ConfigService", "InsideIframeService", "Authmethod", function($state, $stateParams, $http, $scope, $sce, $i18next, ConfigService, InsideIframeService, Authmethod) {
    $scope.inside_iframe = InsideIframeService();
    $scope.documentation = ConfigService.documentation;
    $scope.documentation.security_contact = ConfigService.legal.security_contact;
    $scope.documentation_html_include = $sce.trustAsHtml(ConfigService.documentation_html_include);
    $scope.auths_url = '/election/' + $stateParams.id + '/public/authorities';
    $scope.election_id = $stateParams.id + '';

    Authmethod.viewEvent($stateParams.id)
      .then(function(response) {
        if (response.data.status === "ok") {
          $scope.authEvent = response.data.events;
        }
      });
  }]
);

angular.module('avUi')
  .directive('documentationDirective', function() {
    return {
      restrict: 'AE',
      scope: {
        extra: '='
      },
      templateUrl: 'avUi/documentation-directive/documentation-directive.html',
      controller: 'DocumentationUiController'
    };
  });

/**
 * This file is part of admin-console.
 * Copyright (C) 2015-2016  Sequent Tech Inc <legal@sequentech.io>

 * admin-console is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * admin-console  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with admin-console.  If not, see <http://www.gnu.org/licenses/>.
**/

angular.module('avUi')
  .directive('avFoot', ["ConfigService", function(ConfigService) {
    // we use it as something similar to a controller here
    function link(scope, element, attrs) {
      scope.contact = ConfigService.contact;
      scope.social = ConfigService.social;
      scope.technology = ConfigService.technology;
      scope.legal = ConfigService.legal;
      scope.organization = ConfigService.organization;
    }

    return {
      restrict: 'AE',
      scope: {
      },
      link: link,
      templateUrl: 'avUi/foot-directive/foot-directive.html'
    };
  }]);

/**
 * This file is part of voting-booth.
 * Copyright (C) 2023  Sequent Tech Inc <felix@sequentech.io>

 * voting-booth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * voting-booth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with voting-booth.  If not, see <http://www.gnu.org/licenses/>.
**/

/*
 * i18n-override directive.
 */

angular
  .module('avUi')
  .filter(
    'customI18n',
    function()
    {
      function customI18nFilter(data, key)
      {
        var suffix = "_i18n";
        var lang = window.i18next.resolvedLanguage;
        var value = '';
        if (_.isString(key) && _.isObject(data) && _.isString(lang)) {
            value = data[key + suffix] && data[key + suffix][lang] || data[key] || value;
        }
        return value;
      }
      customI18nFilter.$stateful = true;
      return customI18nFilter;
    }
  );


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

angular.module(
  'common-ui',
  ['ui.bootstrap',
  'ui.utils',
  'ui.router',
  'ngAnimate',
  'ngResource',
  'ngCookies',
  'ipCookie',
  'ngSanitize',
  'infinite-scroll',
  'angularMoment',
  'SequentConfig',
  'jm.i18next',
  'avRegistration',
  'avUi',
  'avTest',
  'angularFileUpload',
  'dndLists',
  'angularLoad',
  'ng-autofocus'
]);

angular.module('common-ui').run(["$http", "$rootScope", function($http, $rootScope) {

  $rootScope.safeApply = function(fn) {
    var phase = $rootScope.$$phase;
    if (phase === '$apply' || phase === '$digest') {
      if (fn && (typeof(fn) === 'function')) {
        fn();
      }
    } else {
      this.$apply(fn);
    }
  };

  $rootScope.$on('$stateChangeStart',
    function(event, toState, toParams, fromState, fromParams) {
      console.log("change start from " + fromState.name + " to " + toState.name);
      $("#angular-preloading").show();
    });
  $rootScope.$on('$stateChangeSuccess',
    function(event, toState, toParams, fromState, fromParams) {
      console.log("change success");
      $("#angular-preloading").hide();
    });
}]);

/*
This directive will trigger a click if the user presses space or enter
 */
angular.module('common-ui').directive('ngSpaceClick', ["$timeout", function ($timeout) {
  return function (scope, element, attrs) {
    element.bind("keydown", function (event) {
      switch (event.which) {
        case 13:              // ENTER
        case 32: {            // SPACE
          $timeout(function() {event.currentTarget.click();},0);
          event.stopPropagation();
        }
      }
    });
  };
}]);

/*
This directive allows us to pass a function in on an enter key to do what we want.
 */
angular.module('common-ui').directive('ngEnter', function () {
    return function (scope, element, attrs) {
        element.bind("keydown keypress", function (event) {
            if(event.which === 13) {
                scope.$apply(function (){
                    scope.$eval(attrs.ngEnter);
                });

                event.preventDefault();
            }
        });
    };
});

/**
 * Truncate Filter
 * @Param text
 * @Param length, default is 10
 * @Param end, default is "..."
 * @return string
 */
angular.module('common-ui').filter('truncate', function () {
        return function (text, length, end) {
            if (isNaN(length)) {
                length = 10;
            }

            if (end === undefined) {
                end = "...";
            }

            if (text.length <= length || text.length - end.length <= length) {
                return text;
            }
            else {
                return String(text).substring(0, length-end.length) + end;
            }

        };
    });

/*globals SequentConfigData:false, $buo:false */
/**
 * Check browser version with browser-update.org
 */
function $buo_f() {
  $buo(SequentConfigData.browserUpdate);
}

if (SequentConfigData.browserUpdate) {
  try {
    document.addEventListener("DOMContentLoaded", $buo_f, false);
  } catch (e) {
    window.attachEvent("onload", $buo_f);
  }
}

angular.module('avTest', []);
/*
 * UnitTestE2EController, that allows E2E unit tests to inject code for testing
 * purposes.
 */

angular.module('avTest')
  .controller('UnitTestE2EController',
    ["$scope", "$location", "ConfigService", function($scope, $location, ConfigService) {
      if (ConfigService.debug) {
        $scope.html = ($location.search()).html;
        console.log($location.search());
      }
    }]);

angular.module('common-ui').run(['$templateCache', function($templateCache) {
  'use strict';

  $templateCache.put('avRegistration/error.html',
    "<div av-simple-error><p ng-i18next=\"avRegistration.errorRegistration\"></p></div>"
  );


  $templateCache.put('avRegistration/field-directive/field-directive.html',
    "<div ng-switch=\"field.type\"><div avr-email-field ng-switch-when=\"email\"></div><div avr-password-field ng-switch-when=\"password\"></div><div avr-code-field ng-switch-when=\"code\"></div><div avr-text-field ng-switch-when=\"text\"></div><div avr-dni-field ng-switch-when=\"dni\"></div><div avr-date-field ng-switch-when=\"date\"></div><div avr-tel-field ng-switch-when=\"tlf\"></div><div avr-int-field ng-switch-when=\"int\"></div><div avr-bool-field ng-switch-when=\"bool\"></div><div avr-captcha-field ng-switch-when=\"captcha\"></div><div avr-textarea-field ng-switch-when=\"textarea\"></div><div avr-image-field ng-switch-when=\"image\"></div></div>"
  );


  $templateCache.put('avRegistration/fields/bool-field-directive/bool-field-directive.html',
    "<div class=\"form-group\"><label><input type=\"checkbox\" class=\"form-control\" aria-labeledby=\"label-{{index}}Text\" id=\"{{index}}Text\" ng-model=\"field.value\" ng-disabled=\"field.disabled\" tabindex=\"0\" ng-required=\"{{field.required}}\"></label><div class=\"bool-text-content\"><label class=\"text-left\" for=\"{{index}}Text\" id=\"label-{{index}}Text\"><span ng-bind-html=\"(field | customI18n : 'name') | addTargetBlank\"></span></label><p class=\"help-block\" ng-if=\"field.help\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><div class=\"input-error\"></div></div></div>"
  );


  $templateCache.put('avRegistration/fields/captcha-field-directive/captcha-field-directive.html',
    "<div class=\"form-group\"><div class=\"col-sm-8 col-sm-offset-4\"><img ng-src=\"{{authMethod.captcha_image_url}}\" style=\"width:161px;height:65px\"></div><label id=\"label-{{index}}Text\" for=\"{{index}}Text\"><span>{{field | customI18n : 'name'}}</span></label><div><input type=\"text\" class=\"form-control\" aria-labeledby=\"label-{{index}}Text\" id=\"{{index}}Text\" minlength=\"{{field.min}}\" maxlength=\"{{field.max}}\" ng-model=\"field.value\" ng-disabled=\"field.disabled\" autocomplete=\"off\" tabindex=\"0\" required><p class=\"help-block\" ng-if=\"field.help\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><div class=\"input-error\">{{authMethod.captcha_status}}</div></div></div>"
  );


  $templateCache.put('avRegistration/fields/code-field-directive/code-field-directive.html',
    "<div class=\"form-group\"><label id=\"{{code_id}}-code\" for=\"{{code_id}}\" ng-i18next=\"avRegistration.codeLabel\"></label><div><input type=\"text\" class=\"form-control\" aria-labeledby=\"{{code_id}}-code\" id=\"{{code_id}}\" ng-model=\"field.value\" ng-disabled=\"field.disabled\" tabindex=\"0\" autocomplete=\"off\" ng-class=\"{'filled': form[code_id].$viewValue.length > 0}\" minlength=\"8\" maxlength=\"9\" ng-pattern=\"codePattern\" name=\"{{code_id}}\" ng-i18next=\"[placeholder]avRegistration.codePlaceholder\" required><p class=\"help-block\" ng-if=\"!field.help || field.help.length === 0\" ng-i18next=\"avRegistration.codeHelp\"></p><p class=\"help-block\" ng-if=\"!!field.help && field.help.length > 0\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><p class=\"help-block code-help\" ng-if=\"allowUserResend && showResendAuthCode() && !sendingData && ((method !== 'sms' && method !== 'sms-otp') || isValidTel)\"><span><b ng-i18next=\"avRegistration.noCodeReceivedQuestion\"></b> <a ng-click=\"resendAuthCode(field)\" ng-i18next=\"avRegistration.sendCodeAgain\"></a> <span></span></span></p><div class=\"input-error\"></div></div></div>"
  );


  $templateCache.put('avRegistration/fields/date-field-directive/date-field-directive.html',
    "<div class=\"form-group\"><label ng-if=\"!label\">{{field | customI18n : 'name'}}</label> <label ng-if=\"label\" ng-bind=\"label\"></label><div><select aria-label=\"{{field.name}}-year\" ng-model=\"date.year\" ng-change=\"onChange()\" ng-disabled=\"field.disabled\"><option ng-selected=\"date.year == item\" ng-repeat=\"item in getYears()\" ng-value=\"item\">{{item}}</option></select> <select aria-label=\"{{field.name}}-month\" ng-model=\"date.month\" ng-change=\"onChange()\" ng-disabled=\"field.disabled\"><option ng-selected=\"date.month == item\" ng-repeat=\"item in getMonths()\" ng-value=\"item\">{{item}}</option></select> <select aria-label=\"{{field.name}}-day\" ng-model=\"date.day\" ng-change=\"onChange()\" ng-disabled=\"field.disabled\"><option ng-selected=\"date.day == item\" ng-repeat=\"item in getDays()\" ng-value=\"item\">{{item}}</option></select><p class=\"help-block\" ng-if=\"field.help\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p></div></div>"
  );


  $templateCache.put('avRegistration/fields/dni-field-directive/dni-field-directive.html',
    "<ng-form name=\"fieldForm\"><div class=\"form-group\" ng-class=\"{'has-error': fieldForm.input.$dirty && fieldForm.input.$invalid}\"><label id=\"label-input{{index}}\" for=\"input{{index}}\"><span>{{field | customI18n : 'name'}}</span></label><div><input type=\"text\" id=\"input{{index}}\" aria-labeledby=\"label-input{{index}}\" class=\"form-control\" minlength=\"{{field.min}}\" maxlength=\"{{field.max}}\" ng-model=\"field.value\" ng-model-options=\"{debounce: 500}\" ng-disabled=\"field.disabled\" tabindex=\"0\" autocomplete=\"off\" ui-validate=\"{dni: 'validateDni($value)'}\" ng-required=\"{{field.required}}\"><p class=\"help-block\" ng-if=\"!field.help || field.help.length === 0\" ng-i18next=\"avRegistration.dniHelp\"></p><p class=\"help-block\" ng-if=\"!!field.help && field.help.length > 0\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><div class=\"input-error\"><span class=\"error text-brand-danger\" ng-show=\"fieldForm.input.$dirty && fieldForm.input.$invalid\" ng-i18next=\"avRegistration.invalidDni\"></span></div></div></div></ng-form>"
  );


  $templateCache.put('avRegistration/fields/email-field-directive/email-field-directive.html',
    "<div class=\"form-group\" ng-class=\"{true: 'has-error',false: 'is-required'}[form.emailText.$dirty && form.emailText.$invalid]\"><label for=\"emailText\" id=\"label-emailText\" ng-i18next=\"avRegistration.emailLabel\"></label><div><input type=\"text\" class=\"form-control\" ng-model=\"field.value\" name=\"emailText\" id=\"emailText\" aria-labelledby=\"label-emailText\" ng-i18next=\"[placeholder]avRegistration.emailPlaceholder\" tabindex=\"0\" autocomplete=\"off\" ng-pattern=\"emailRe\" required ng-disabled=\"field.disabled\"><p class=\"text-warning\" ng-if=\"'email-otp' === method && (!field.help || field.help.length === 0)\" ng-i18next=\"avRegistration.otpHelp\"></p><p class=\"help-block\" ng-if=\"!!field.help && field.help.length > 0\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><div class=\"input-error\"><small class=\"error text-danger\" role=\"alert\" ng-show=\"form.emailText.$dirty && form.emailText.$invalid\" ng-i18next=\"avRegistration.emailError\"></small></div></div></div>"
  );


  $templateCache.put('avRegistration/fields/image-field-directive/image-field-directive.html',
    "<ng-form name=\"fieldForm\"><div class=\"form-group\" ng-class=\"{'has-error': fieldForm.input.$dirty && fieldForm.input.$invalid}\"><label id=\"label-image-field\" for=\"image-field\"><span>{{field | customI18n : 'name'}}</span></label><div><input type=\"file\" name=\"image\" id=\"image-field\" aria-labeledby=\"label-image-field\" class=\"form-control\" ng-disabled=\"field.disabled\" tabindex=\"0\" ng-required=\"{{field.required}}\"><p class=\"help-block\" ng-if=\"!field.help || field.help.length === 0\" ng-i18next=\"avRegistration.imageHelp\"></p><p class=\"help-block\" ng-if=\"!!field.help && field.help.length > 0\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><div class=\"input-error\"><span class=\"error text-brand-danger\" role=\"alert\" ng-show=\"fieldForm.input.$dirty && fieldForm.input.$invalid\" ng-i18next=\"avRegistration.invalidImage\"></span></div></div></div></ng-form>"
  );


  $templateCache.put('avRegistration/fields/int-field-directive/int-field-directive.html',
    "<ng-form name=\"fieldForm\"><div class=\"form-group\" ng-class=\"{'has-error': fieldForm.input.$dirty && fieldForm.input.$invalid}\"><label id=\"label-input{{index}}\" for=\"input{{index}}\"><span>{{field | customI18n : 'name'}}</span></label><div><input type=\"number\" class=\"form-control\" id=\"input{{index}}\" aria-labeledby=\"label-input{{index}}\" name=\"input\" min=\"{{field.min}}\" autocomplete=\"off\" max=\"{{field.max}}\" ng-model=\"field.value\" ng-model-options=\"{debounce: 500}\" ng-disabled=\"field.disabled\" ng-pattern=\"re\" tabindex=\"0\" ng-required=\"{{field.required}}\"><p class=\"help-block\" ng-if=\"!!field.help && field.help.length > 0\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><div class=\"input-error\"><span class=\"error text-brand-danger\" ng-show=\"fieldForm.input.$dirty && fieldForm.input.$invalid\" ng-i18next=\"avRegistration.invalidDataRegEx\"></span></div></div></div></ng-form>"
  );


  $templateCache.put('avRegistration/fields/password-field-directive/password-field-directive.html',
    "<div class=\"form-group\" ng-class=\"{true: 'has-error',false: 'is-required'}[form.passwordText.$dirty && form.passwordText.$invalid]\"><label id=\"label-passwordText\" for=\"passwordText\"><span ng-i18next=\"avRegistration.passwordLabel\"></span></label><div><input type=\"password\" aria-labeledby=\"label-passwordText\" class=\"form-control\" ng-model=\"field.value\" id=\"passwordText\" autocomplete=\"off\" ng-disabled=\"field.disabled\" ng-i18next=\"[placeholder]avRegistration.passwordPlaceholder\" tabindex=\"0\" required><p class=\"help-block\" ng-if=\"!field.no_help\"><a href=\"#\" ng-if=\"!field.help || field.help.length == 0\" ng-i18next=\"avRegistration.forgotPassword\" ng-click=\"forgotPassword()\" tabindex=\"0\"></a></p><p class=\"help-block\" ng-if=\"!!field.help && field.help.length > 0\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><p></p><div class=\"input-error\"><small role=\"alert\" class=\"error text-danger\" ng-show=\"form.$submitted && form.$invalid\" ng-i18next=\"avRegistration.invalidCredentials\"></small></div></div></div>"
  );


  $templateCache.put('avRegistration/fields/tel-field-directive/tel-field-directive.html',
    "<div class=\"form-group\"><label id=\"label-input{{index}}\" for=\"input{{index}}\" ng-i18next=\"avRegistration.telLabel\"></label><div><input type=\"tel\" class=\"form-control phone-login\" aria-labeledby=\"label-input{{index}}\" id=\"input{{index}}\" ng-disabled=\"field.disabled\" tabindex=\"0\" name=\"input{{index}}\" required><p class=\"help-block\" ng-if=\"!field.help || field.help.length === 0\" ng-i18next=\"avRegistration.telHelp\"></p><p class=\"help-block\" ng-if=\"!!(field.help || field.help_i18n) && field.help.length > 0\" ng-bind-html=\"(field | customI18n : 'help') | addTargetBlank\"></p><p class=\"text-warning\" ng-if=\"'sms-otp' === method\" ng-i18next=\"avRegistration.otpHelp\"></p><div class=\"input-error\"><span class=\"error\" ng-show=\"!isValidNumber\" ng-i18next=\"avRegistration.telInvalid\"></span></div></div></div>"
  );


  $templateCache.put('avRegistration/fields/text-field-directive/text-field-directive.html',
    "<ng-form name=\"fieldForm\"><div class=\"form-group\" ng-class=\"{'has-error': fieldForm.input.$dirty && fieldForm.input.$invalid}\"><label id=\"label-input{{index}}\" for=\"input{{index}}\"><span ng-if=\"field.name == 'username' || field.name == '__username'\" ng-i18next=\"avRegistration.usernameLabel\"></span> <span ng-if=\"field.name != 'username' && field.name != '__username'\">{{field | customI18n : 'name'}}</span></label><div><input type=\"text\" name=\"input\" id=\"input{{index}}\" aria-labeledby=\"label-input{{index}}\" class=\"form-control\" minlength=\"{{field.min}}\" maxlength=\"{{field.max}}\" ng-model=\"field.value\" ng-model-options=\"{debounce: 500}\" ng-disabled=\"field.disabled\" tabindex=\"0\" ng-pattern=\"re\" autocomplete=\"off\" ng-required=\"{{field.required}}\"><p class=\"help-block\" ng-if=\"field.help || field.help_i18n\" ng-bind-html=\"field | customI18n : 'help' | addTargetBlank\"></p><div class=\"input-error\"><span class=\"error text-brand-danger\" ng-show=\"fieldForm.input.$dirty && fieldForm.input.$invalid\" ng-i18next=\"avRegistration.invalidDataRegEx\"></span></div></div></div></ng-form>"
  );


  $templateCache.put('avRegistration/fields/textarea-field-directive/textarea-field-directive.html',
    "<div class=\"form-group\"><div class=\"col-sm-offset-2 col-sm-10\"><textarea aria-label=\"{{index}}Text\" id=\"{{index}}Text\" rows=\"5\" cols=\"60\" tabindex=\"0\" readonly>{{field.name}}</textarea><p class=\"help-block\" ng-if=\"field.help || field.help_i18n\" ng-bind-html=\"field | customI18n : 'help' | addTargetBlank\"></p></div></div>"
  );


  $templateCache.put('avRegistration/loading.html',
    "<div avb-busy><p ng-i18next=\"avRegistration.loadingRegistration\"></p></div>"
  );


  $templateCache.put('avRegistration/login-controller/login-controller.html',
    "<div class=\"col-xs-12 login-controller\"><div class=\"pad\"><div av-login event-id=\"{{event_id}}\" code=\"{{code}}\" email=\"{{email}}\" with-code=\"{{withCode}}\" username=\"{{username}}\" is-otl=\"{{isOtl}}\" is-open-id=\"{{isOpenId}}\" otl-secret=\"{{otlSecret}}\" with-alt-method=\"{{withAltMethod}}\" selected-alt-method=\"{{selectedAltMethod}}\"></div><div ng-repeat=\"alt_method in alt_methods\" ng-if=\"!withAltMethod\"><div class=\"separator\" ng-i18next=\"avRegistration.other\"></div><div av-login event-id=\"{{event_id}}\" code=\"{{code}}\" email=\"{{email}}\" with-code=\"{{withCode}}\" username=\"{{username}}\" is-otl=\"{{isOtl}}\" is-open-id=\"{{isOpenId}}\" otl-secret=\"{{otlSecret}}\" with-alt-method=\"true\" selected-alt-method=\"{{alt_method}}\"></div></div></div></div>"
  );


  $templateCache.put('avRegistration/login-directive/login-directive.html',
    "<section class=\"container-login\" aria-labelledby=\"login-header-text\"><div class=\"row\"><div class=\"col-sm-12 loginheader\"><h3 class=\"tex-center login-header-text\" id=\"login-header-text\" ng-if=\"!isAdmin && !isOtl && !isCensusQuery\" ng-i18next=\"[i18next]({name: orgName})avRegistration.loginHeader\"></h3><h3 class=\"tex-center login-header-text\" id=\"login-header-text\" ng-if=\"isAdmin && !isOtl\" ng-i18next=\"[i18next]avRegistration.adminLoginHeader\"></h3><h3 class=\"tex-center login-header-text\" id=\"login-header-text\" ng-if=\"!!isCensusQuery\" ng-i18next=\"avRegistration.censusQueryHeader\"></h3><h3 class=\"tex-center login-header-text\" id=\"login-header-text\" ng-if=\"isOtl\" ng-i18next=\"avRegistration.otlHeader\"></h3><div class=\"text-success\" ng-if=\"!!successfulRegistration\" ng-i18next=\"[html:i18next]avRegistration.loginAfterRegistration\"></div></div><div class=\"col-sm-12\" ng-if=\"method !== 'openid-connect'\"><form name=\"form\" id=\"loginForm\" role=\"form\" class=\"form-horizontal\"><div ng-repeat=\"field in login_fields\" avr-field index=\"{{$index+1}}\" ng-if=\"(field.steps === undefined || field.steps.indexOf(currentFormStep) !== -1) && otlStatus !== 'success'\"></div><div class=\"button-group\"><section class=\"input-error\" ng-if=\"!isCensusQuery\" aria-label=\"{{ 'avRegistration.loginError.errorLabel' | i18next }}\"><div class=\"error text-danger\" role=\"alert\" ng-if=\"error\" ng-i18next>[html:i18next]({{errorData}}){{error}}</div></section><section class=\"input-warn\" aria-label=\"{{ 'avRegistration.loginError.warningLabel' | i18next }}\"><div class=\"warn-box\" ng-if=\"!form.$valid || sendingData\"><span class=\"glyphicon glyphicon-warning-sign\"></span><div role=\"alert\" ng-i18next>avRegistration.fillValidFormText</div></div></section><button type=\"submit\" class=\"btn btn-block btn-lg btn-success-action\" ng-if=\"!isCensusQuery && !isOtl && method !== 'smart-link'\" ng-i18next=\"avRegistration.loginButton\" ng-click=\"loginUser(form.$valid)\" tabindex=\"0\" ng-disabled=\"!form.$valid || sendingData\"></button> <button type=\"submit\" class=\"btn btn-block btn-lg btn-success-action\" ng-if=\"isCensusQuery\" ng-i18next=\"avRegistration.checkCensusButton\" ng-click=\"checkCensus(form.$valid)\" tabindex=\"0\" ng-disabled=\"!form.$valid || sendingData\"></button> <button type=\"submit\" class=\"btn btn-block btn-lg btn-success-action\" ng-if=\"isOtl && otlStatus !== 'success'\" ng-i18next=\"avRegistration.otlButton\" ng-click=\"otlAuth(form.$valid)\" tabindex=\"0\" ng-disabled=\"!form.$valid || sendingData\"></button><div class=\"otl-auth\" ng-if=\"isOtl\"><div class=\"input-info\" ng-if=\"otlStatus == 'querying'\"><div class=\"text-info\" ng-i18next=\"avRegistration.otlStatus.querying\"></div></div><div class=\"input-success\" ng-if=\"otlStatus == 'success'\"><div class=\"success text-success\" ng-i18next=\"[html:i18next]({code: otpCode})avRegistration.otlStatus.success\"></div></div><div class=\"input-success\" ng-if=\"otlStatus == 'fail'\"><div class=\"error text-danger\" role=\"alert\" ng-i18next=\"[html]avRegistration.otlStatus.fail\"></div></div></div><div class=\"census-query\" ng-if=\"isCensusQuery\"><div class=\"input-info census-query\" ng-if=\"censusQuery == 'querying'\"><div class=\"text-info\" ng-i18next=\"avRegistration.censusQuerying\"></div></div><div class=\"input-success census-query\" ng-if=\"censusQuery == 'success'\"><div class=\"success text-success\" ng-i18next=\"[html]avRegistration.censusSuccess\"></div></div><div class=\"input-success census-query\" ng-if=\"censusQuery == 'fail'\"><div class=\"error text-danger\" role=\"alert\" ng-i18next=\"[html]avRegistration.censusFail\"></div></div></div></div></form></div><div class=\"col-sm-5 col-sm-offset-1 hidden-xs not-registered-yet\" ng-if=\"registrationAllowed && !isCensusQuery && method !== 'openid-connect' && !isOtl\"><h3 class=\"help-h3\" ng-i18next=\"avRegistration.notRegisteredYet\"></h3><p><a ng-if=\"!isAdmin\" href=\"/election/{{election.id}}/public/register\" ng-i18next=\"avRegistration.registerHere\" ng-click=\"goSignup()\" tabindex=\"0\"></a><br><a ng-if=\"isAdmin\" href=\"{{ signupLink }}\" ng-i18next=\"avRegistration.registerHere\" tabindex=\"0\"></a><br><span ng-i18next=\"avRegistration.fewMinutes\"></span></p></div><div class=\"col-sm-12 text-center oidc-section\" ng-if=\"method === 'openid-connect'\"><p class=\"oidc-login-description\" ng-i18next=\"[html]avRegistration.openidLoginDescription\"></p><span ng-repeat=\"provider in current_oidc_providers\" class=\"provider-span\"><button ng-click=\"openidConnectAuth(provider)\" alt=\"{{provider.public_info.description}}\" tabindex=\"0\" class=\"btn btn-block btn-lg provider-btn\" ng-class=\"{[provider.public_info.id]: true}\"><img ng-if=\"!!provider.public_info.icon\" alt=\"{{provider.public_info.description}}\" ng-src=\"{{provider.public_info.icon}}\"> {{provider.public_info.title}}</button></span><div class=\"button-group\"><div class=\"input-error\"><div class=\"error text-danger\" role=\"alert\" ng-if=\"error\" ng-i18next>[html:i18next]({{errorData}}){{error}}</div></div></div></div></div></section>"
  );


  $templateCache.put('avRegistration/register-controller/register-controller.html',
    "<div class=\"col-xs-12 top-section\"><div class=\"pad\"><div av-register event-id=\"{{event_id}}\" code=\"{{code}}\" email=\"{{email}}\"></div></div></div>"
  );


  $templateCache.put('avRegistration/register-directive/register-directive.html',
    "<div class=\"container\"><div class=\"row\"><div class=\"col-sm-12\"><h2 ng-if=\"!admin\" class=\"registerheader\" ng-i18next=\"avRegistration.registerHeader\"></h2><h2 ng-if=\"admin\" class=\"registerheader\" ng-i18next=\"avRegistration.registerAdminHeader\"></h2></div></div><div class=\"row\"><div class=\"col-sm-6\"><div ng-if=\"method == 'dnie'\"><a type=\"submit\" class=\"btn btn-block btn-success\" ng-i18next=\"avRegistration.registerButton\" ng-href=\"{{ dnieurl }}/\"></a></div><form ng-if=\"method != 'dnie'\" name=\"form\" id=\"registerForm\" role=\"form\" class=\"form-horizontal\"><div ng-repeat=\"field in register_fields\" avr-field index=\"{{$index+1}}\"></div><div class=\"col-sm-12 button-group\"><div class=\"input-error\"><div class=\"error text-danger\" role=\"alert\" ng-if=\"error\" ng-bind-html=\"error\"></div></div><div class=\"input-warn\"><span class=\"text-warning\" ng-if=\"!form.$valid || sendingData\" ng-i18next>avRegistration.fillValidFormText</span></div><button type=\"submit\" class=\"btn btn-block btn-success\" ng-i18next=\"avRegistration.registerButton\" ng-click=\"signUp(form.$valid)\" tabindex=\"0\" ng-disabled=\"!form.$valid || sendingData\"></button></div></form></div><div class=\"col-sm-5 col-sm-offset-1 help-sidebar hidden-xs\"><span ng-if=\"admin\"><h3 class=\"help-h3\" ng-i18next=\"avRegistration.registerAdminFormHelpTitle\"></h3><p ng-i18next>avRegistration.helpAdminRegisterForm</p></span><span><p ng-if=\"!admin\" ng-i18next>avRegistration.helpRegisterForm</p><h3 class=\"help-h3\" ng-i18next=\"avRegistration.alreadyRegistered\"></h3><p ng-i18next>[html]avRegistration.helpAlreadyRegisteredForm</p><a href=\"\" ng-click=\"goLogin($event)\" ng-i18next=\"avRegistration.loginHere\"></a><br></span></div></div></div>"
  );


  $templateCache.put('avRegistration/success.html',
    "<div av-success><p ng-i18next=\"avRegistration.successRegistration\"></p></div>"
  );


  $templateCache.put('avUi/change-lang-directive/change-lang-directive.html',
    "<a href=\"#\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" id=\"lang-dropdown-toggle\" role=\"button\" aria-expanded=\"false\" aria-label=\"{{ ('avCommon.changeLanguageMenu' | i18next) || 'Change Language' }}\"><i class=\"fa fa-fw fa-lg fa-language\"></i> <span class=\"selected-lang hidden-xs\">{{ ('avRegistration.languageName' | i18next) || deflang }}</span> <span class=\"caret\"></span></a><ul class=\"dropdown-menu\" role=\"menu\"><li ng-repeat=\"lang in langs\"><a role=\"menuitem\" ng-click=\"changeLang(lang)\" ng-space-click tabindex=\"0\">{{ ('avRegistration.languageName' | i18next:{lng:lang}) || lang}}</a></li></ul>"
  );


  $templateCache.put('avUi/children-elections-directive/children-elections-directive.html',
    "<div class=\"row\" ng-if=\"mode === 'toggle-and-callback' && !hideParent\"><div class=\"col-xs-12\"><div class=\"btn btn-success btn-election\" ng-class=\"{'selected': selectedElectionId === parentElectionId}\" ng-click=\"click({event_id: parentElectionId})\"><span ng-i18next>avAdmin.childrenElections.main</span></div></div></div><div ng-repeat=\"category in childrenElectionInfo.presentation.categories\" ng-if=\"!category.hidden\" class=\"row\"><div class=\"col-xs-12\"><h3>{{category.title}}</h3><div ng-repeat=\"election in category.events\" class=\"btn btn-success btn-election\" ng-disabled=\"election.disabled\" ng-if=\"!election.hidden\" ng-class=\"{'selected': selectedElectionId === election.event_id}\" data-election-id=\"{{election.event_id}}\" ng-click=\"click(election)\"><i ng-if=\"mode === 'checkbox'\" class=\"fa-fw fa\" ng-class=\"{'fa-square-o': !election.data, 'fa-check-square-o': !!election.data}\" aria-hidden=\"true\"></i> {{election.title}}</div></div></div>"
  );


  $templateCache.put('avUi/common-footer-directive/common-footer-directive.html',
    "<div class=\"hidden\" ng-cloak av-affix-bottom ng-if=\"!float\" class=\"footer-wrapper\"><footer class=\"container footer-container row\" role=\"navigation\"><i ng-i18next=\"[html:i18next]({url: configService.organization.orgUrl, name: configService.organization.orgName})avCommon.poweredBy\"></i></footer></div><div ng-if=\"!!float\" class=\"footer-wrapper\"><footer class=\"container footer-container row\" role=\"navigation\"><i ng-i18next=\"[html:i18next]({url: configService.organization.orgUrl, name: configService.organization.orgName})avCommon.poweredBy\"></i></footer></div>"
  );


  $templateCache.put('avUi/common-header-directive/common-header-directive.html',
    "<!-- top navbar --><nav class=\"header-navbar\" id=\"header-navbar\" av-affix-top=\".navbar-unfixed-top\" role=\"navigation\"><div class=\"header-container container\"><div class=\"col-xs-4 header-left\"><span class=\"logo-img-container\" ng-class=\"{'default-logo': !election.logo_url}\"><img alt=\"{{election.title}}\" class=\"logo-img\" ng-src=\"{{election.logo_url || defaultLogo}}\"></span></div><div class=\"col-xs-8 header-right\"><div class=\"hidden-xs social-container\" ng-if=\"!!isElectionPortal && !!buttonsInfo\"><span ng-repeat=\"q in buttonsInfo\"><a href=\"{{ q.link }}\" target=\"_blank\" class=\"{{ q.class }}\"><img class=\"social-img\" ng-src=\"{{ q.img }}\" alt=\"{{ q.network }}\"> {{ q.button_text|truncate:25 }}</a></span></div><a ng-if=\"!!configService.mainVersion\" target=\"_top\" tabindex=\"0\" class=\"config-version\" role=\"button\" ng-click=\"showVersionsModal()\"><span class=\"hidden-xs\" ng-i18next=\"[i18next]({version: configService.mainVersion})avCommon.showVersion\"></span> <span class=\"visible-xs-block\">{{configService.mainVersion}} </span></a><span class=\"dropdown\" role=\"menuitem\" av-change-lang></span> <span class=\"logout-container\" ng-if=\"enableLogOut() && !isElectionPortal\" ng-class=\"{ 'countdown': showCountdown}\"><a target=\"_top\" tabindex=\"0\" class=\"log-out-button\" ng-click=\"confirmLogoutModal()\"><div class=\"logout-bottom\"></div><div class=\"logout-bar\"></div><span class=\"glyphicon glyphicon-off\"></span> <span class=\"logout-text hidden-xs\" ng-i18next>avBooth.logout</span></a><div class=\"custom-tooltip\"><i class=\"fa fa-fw fa-lg fa-caret-up\"></i><div class=\"tooltip-inner\"><b ng-i18next>avBooth.countdownTooltip.title</b><p ng-if=\"countdownSecs >= 60\" ng-i18next=\"[i18next]({mins: countdownMins})avBooth.countdownTooltip.contentMins\"></p><p ng-if=\"countdownSecs < 60\" ng-i18next=\"[i18next]({secs: countdownSecs})avBooth.countdownTooltip.contentSecs\"></p></div></div></span></div></div></nav><div id=\"avb-toggle\" class=\"text-center item-block hidden\"><span class=\"glyphicon glyphicon-play\"></span></div><div class=\"bottom-absolute\" ng-if=\"ballotHash\"><div class=\"ballot-hash\"><div class=\"hash-box\"><i class=\"fa fa-check\" aria-hidden=\"true\"></i><div class=\"hash-text\" ng-i18next=\"[i18next]({hash: ballotHash})avBooth.reviewScreen.ballotIdMessage\"></div><i class=\"pull-right fa fa-lg fa-question-circle\" ng-click=\"hashHelp()\"></i></div></div></div>"
  );


  $templateCache.put('avUi/confirm-modal-controller/confirm-modal-controller.html',
    "<div class=\"confirm-modal-controller\"><div class=\"modal-header dialog-header-warning\"><h4 class=\"modal-title\"><span class=\"glyphicon glyphicon-warning-sign\"></span> <span class=\"title\" ng-bind-html=\"data.i18n.header\"></span> <button type=\"button\" class=\"close pull-right\" ng-click=\"cancel()\"><i class=\"fa fa-times-circle\"></i></button></h4></div><div class=\"modal-body\"><p><span class=\"body-data\" ng-bind-html=\"data.i18n.body\"></span></p></div><div class=\"modal-footer\"><button class=\"btn btn-success\" ng-click=\"ok()\">{{ data.i18n.confirmButton }}</button> <button class=\"btn btn-cancel\" ng-click=\"cancel()\" ng-if=\"!data.hideCancelButton\" ng-i18next=\"avCommon.cancel\">avCommon.cancel</button></div></div>"
  );


  $templateCache.put('avUi/documentation-directive/documentation-directive.html',
    "<div><h2 class=\"text-center text-av-secondary\" ng-i18next=\"avDocumentation.documentation.title\"></h2><p ng-i18next=\"avDocumentation.documentation.first_line\"></p><ul class=\"docu-ul\"><li ng-if=\"!!documentation.faq\"><a href=\"{{documentation.faq}}\" target=\"_blank\" ng-i18next=\"avDocumentation.documentation.faq\"></a></li><li ng-if=\"!!documentation.overview\"><a href=\"{{documentation.overview}}\" target=\"_blank\" ng-i18next=\"avDocumentation.documentation.overview\"></a></li><li><a href=\"{{auths_url}}\" target=\"_blank\" ng-i18next=\"avDocumentation.documentation.authorities\"></a></li><li ng-if=\"!!documentation.technical\"><a href=\"{{documentation.technical}}\" target=\"_blank\" ng-i18next=\"avDocumentation.documentation.technical\"></a></li><li ng-if=\"!!documentation.security_contact\"><a href=\"{{documentation.security_contact}}\" target=\"_blank\" ng-i18next=\"avDocumentation.documentation.security_contact\"></a></li></ul><div class=\"documentation-html-include\" av-plugin-html ng-bind-html=\"documentation_html_include\"></div></div>"
  );


  $templateCache.put('avUi/foot-directive/foot-directive.html',
    "<div class=\"commonfoot\"><div class=\"social\" style=\"text-align: center;\"><span class=\"powered-by pull-left\" ng-i18next=\"[html:i18next]({url: organization.orgUrl, name: organization.orgName})avCommon.poweredBy\"></span> <a href=\"{{social.facebook}}\" target=\"_blank\" ng-if=\"!!social.facebook\" aria-label=\"Facebook\"><i class=\"fa fa-fw fa-lg fa-facebook\"></i></a> <a href=\"{{social.twitter}}\" target=\"_blank\" ng-if=\"!!social.twitter\" aria-label=\"Twitter\"><i class=\"fa fa-fw fa-lg fa-twitter\"></i></a> <a href=\"{{social.googleplus}}\" target=\"_blank\" ng-if=\"!!social.googleplus\" aria-label=\"Google Plus\"><i class=\"fa fa-fw fa-lg fa-google-plus\"></i></a> <a href=\"{{social.youtube}}\" target=\"_blank\" ng-if=\"!!social.youtube\" aria-label=\"Youtube\"><i class=\"fa fa-fw fa-lg fa-youtube-play\"></i></a> <a href=\"{{social.github}}\" target=\"_blank\" ng-if=\"!!social.github\" aria-label=\"Github\"><i class=\"fa fa-fw fa-lg fa-github\"></i></a></div></div>"
  );


  $templateCache.put('avUi/simple-error-directive/simple-error-directive.html',
    "<div class=\"av-simple-error-title\" ng-transclude></div>"
  );


  $templateCache.put('test/test_booth_widget.html',
    "<!DOCTYPE html><html><head><title>Test frame</title><meta charset=\"UTF-8\"></head><script>function getCastHmac(auth_data, callback) {\n" +
    "      callback(\"khmac:///sha-256;5e25a9af28a33d94b8c2c0edbc83d6d87355e45b93021c35a103821557ec7dc5/voter-1110-1dee0c135afeae29e208550e7258dab7b64fb008bc606fc326d41946ab8e773f:1415185712\");\n" +
    "    }</script><body style=\"overflow-y: hidden; overflow-x: hidden; padding: 0; margin: 0\"><div style=\"width: 100%; display: block; position: absolute; top: 0; bottom: 0; scroll: none; padding: 0; margin: 0\"><a class=\"sequent-voting-booth\" href=\"http://sequent.dev/#/election/1110/vote\" data-authorization-funcname=\"getCastHmac\">Votar con Sequent Tech</a><script>!function(d,s,id){var js,fjs=d.getElementsByTagName(s)[0];if(!d.getElementById(id)){js=d.createElement(s);js.id=id;js.src=\"http://sequent.dev/avWidgets.min.js\";fjs.parentNode.insertBefore(js,fjs);}}(document,\"script\",\"sequent-widgets-js\");</script></div></body></html>"
  );


  $templateCache.put('test/unit_test_e2e.html',
    "<div dynamic=\"html\" id=\"dynamic-result\"></div>"
  );

}]);
