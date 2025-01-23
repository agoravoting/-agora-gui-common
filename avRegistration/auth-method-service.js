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

    .factory('Authmethod', function(
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

        authmethod.scheduledEvent = function(eid, data) {
            var url = backendUrl + 'auth-event/'+eid+'/scheduled-event/';
            if (data === undefined) {
              data = {};
            }
            return $http.post(url, data);
        };

        authmethod.deleteElections = function(electionIds) {
            var url = backendUrl + 'auth-event/delete-elections/';
            var data = {"election-ids": electionIds};
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
