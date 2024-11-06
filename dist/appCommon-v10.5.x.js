function $buo_f() {
    $buo(SequentConfigData.browserUpdate);
}

if (angular.module("avRegistration", [ "ui.bootstrap", "ui.utils", "ui.router" ]), 
angular.module("avRegistration").config(function() {}), angular.module("avRegistration").factory("Authmethod", [ "$http", "$cookies", "$window", "ConfigService", "$interval", "$state", "$location", "$document", "$q", function($http, $cookies, $window, ConfigService, $interval, $state, $location, $document, $q) {
    var backendUrl = ConfigService.authAPI, authId = ConfigService.freeAuthId, authmethod = {};
    function hasPassedHalfLifeExpiry(now, halfLifes) {
        halfLifes = function(isAdmin) {
            var credentialsStr = $window.sessionStorage.getItem("vote_permission_tokens"), tokens = [];
            return credentialsStr ? JSON.parse(credentialsStr).map(function(credential) {
                return credential.token;
            }).filter(function(token) {
                return !!token;
            }) : (isAdmin && $http.defaults.headers.common.Authorization && tokens.push($http.defaults.headers.common.Authorization), 
            tokens);
        }(halfLifes);
        if (0 !== halfLifes.length) {
            halfLifes = halfLifes.map(function(decodedToken) {
                decodedToken = authmethod.decodeToken(decodedToken);
                return 1e3 * (decodedToken.expiry_timestamp + decodedToken.create_timestamp) / 2;
            });
            return Math.min.apply(null, halfLifes) < now;
        }
    }
    authmethod.captcha_code = null, authmethod.captcha_image_url = "", authmethod.captcha_status = "", 
    authmethod.admin = !1, authmethod.decodeToken = function(createTimestamp) {
        var subMessage = createTimestamp.split("///");
        if (2 !== subMessage.length) throw new Error("Invalid token format");
        var expiryTimestamp = subMessage[1].split("/");
        if (2 !== expiryTimestamp.length) throw new Error("Invalid message format");
        createTimestamp = expiryTimestamp[1].split(":");
        if (createTimestamp.length < 4) throw new Error("Invalid message format");
        subMessage = createTimestamp.slice(0, createTimestamp.length - 3).join(":"), expiryTimestamp = parseInt(createTimestamp[createTimestamp.length - 3], 10), 
        createTimestamp = parseInt(createTimestamp[createTimestamp.length - 1], 10);
        return {
            message: subMessage,
            create_timestamp: createTimestamp,
            expiry_timestamp: expiryTimestamp,
            expiry_secs_diff: expiryTimestamp - createTimestamp
        };
    }, authmethod.getAuthevent = function() {
        var adminId = ConfigService.freeAuthId + "", electionsMatch = $location.path(), authevent = "", adminMatch = electionsMatch.match(/^\/admin\//), boothMatch = electionsMatch.match(/^\/booth\/([0-9]+)\//), electionsMatch = electionsMatch.match(/^\/(elections|election)\/([0-9]+)\//);
        return _.isArray(adminMatch) ? authevent = adminId : _.isArray(boothMatch) && 2 === boothMatch.length ? authevent = boothMatch[1] : _.isArray(electionsMatch) && 3 === electionsMatch.length && (authevent = electionsMatch[2]), 
        authevent;
    }, authmethod.setAuth = function(auth, isAdmin, autheventid) {
        var callback;
        if (authmethod.admin = isAdmin, $http.defaults.headers.common.Authorization = auth, 
        authmethod.lastAuthDate = new Date(), !authmethod.iddleDetectionSetup) return authmethod.iddleDetectionSetup = !0, 
        callback = function() {
            var now = new Date();
            hasPassedHalfLifeExpiry(now.getTime(), isAdmin) && (authmethod.lastAuthDate = now, 
            authmethod.refreshAuthToken(autheventid));
        }, [ "click", "keypress", "mousemove", "mousedown", "touchstart", "touchmove" ].forEach(function(event) {
            document.addEventListener(event, callback);
        }), !1;
    }, authmethod.isAdmin = function() {
        return authmethod.isLoggedIn() && authmethod.admin;
    }, authmethod.isLoggedIn = function() {
        var auth = $http.defaults.headers.common.Authorization;
        return auth && 0 < auth.length;
    }, authmethod.signup = function(data, eid) {
        eid = eid || authId;
        return $http.post(backendUrl + "auth-event/" + eid + "/register/", data);
    }, authmethod.createLivePreview = function(data) {
        return $http.post(backendUrl + "auth-event/live-preview/", data);
    }, authmethod.getLivePreview = function(url) {
        url = backendUrl + "auth-event/" + url + "/live-preview/";
        return $http.get(url);
    }, authmethod.getUserInfoExtra = function() {
        if (authmethod.isLoggedIn()) return $http.get(backendUrl + "user/extra/", {});
        var data = {
            then: function(onSuccess, onError) {
                return setTimeout(function() {
                    onError({
                        data: {
                            message: "not-logged-in"
                        }
                    });
                }, 0), data;
            }
        };
        return data;
    }, authmethod.highestEvent = function() {
        var url = backendUrl + "auth-event/highest/";
        return $http.get(url);
    }, authmethod.getActivity = function(url, page, size, filterOptions, filterStr, receiver_id) {
        var params = {}, url = backendUrl + "auth-event/" + url + "/activity/";
        return "max" === size ? params.n = 500 : angular.isNumber(size) && 0 < size && size < 500 ? params.n = parseInt(size) : params.n = 50, 
        angular.isNumber(page) ? params.page = parseInt(page) : params.page = 1, angular.isNumber(receiver_id) && (params.receiver_id = receiver_id), 
        _.extend(params, filterOptions), filterStr && 0 < filterStr.length && (params.filter = filterStr), 
        $http.get(url, {
            params: params
        });
    }, authmethod.getBallotBoxes = function(url, page, size, filterOptions, filterStr) {
        var params = {}, url = backendUrl + "auth-event/" + url + "/ballot-box/";
        return "max" === size ? params.n = 500 : angular.isNumber(size) && 0 < size && size < 500 ? params.n = parseInt(size) : params.n = 50, 
        angular.isNumber(page) ? params.page = parseInt(page) : params.page = 1, _.extend(params, filterOptions), 
        filterStr && 0 < filterStr.length && (params.filter = filterStr), $http.get(url, {
            params: params
        });
    }, authmethod.createBallotBox = function(url, params) {
        params = {
            name: params
        }, url = backendUrl + "auth-event/" + url + "/ballot-box/";
        return $http.post(url, params);
    }, authmethod.obtainVoterAuthCode = function(url, params) {
        params = {
            username: params
        }, url = backendUrl + "auth-event/" + url + "/generate-auth-code/";
        return $http.post(url, params);
    }, authmethod.resetVotersToPreRegistration = function(url, voterIds, params) {
        params = {
            "user-ids": voterIds,
            comment: params
        }, url = backendUrl + "auth-event/" + url + "/census/reset-voter/";
        return $http.post(url, params);
    }, authmethod.postTallySheet = function(eid, url, data) {
        url = backendUrl + "auth-event/" + eid + "/ballot-box/" + url + "/tally-sheet/";
        return $http.post(url, data);
    }, authmethod.voteStats = function(url) {
        url = backendUrl + "auth-event/" + url + "/vote-stats/";
        return $http.get(url);
    }, authmethod.suspend = function(url) {
        url = backendUrl + "auth-event/" + url + "/suspended/";
        return $http.post(url);
    }, authmethod.resume = function(url) {
        url = backendUrl + "auth-event/" + url + "/resumed/";
        return $http.post(url);
    }, authmethod.scheduledEvents = function(url, scheduledEvents) {
        url = backendUrl + "auth-event/" + url + "/scheduled-events/";
        return $http.post(url, scheduledEvents);
    }, authmethod.getTallySheet = function(eid, ballot_box_id, tally_sheet_id) {
        var url = null, url = tally_sheet_id ? backendUrl + "auth-event/" + eid + "/ballot-box/" + ballot_box_id + "/tally-sheet/" + tally_sheet_id + "/" : backendUrl + "auth-event/" + eid + "/ballot-box/" + ballot_box_id + "/tally-sheet/";
        return $http.get(url);
    }, authmethod.deleteTallySheet = function(eid, ballot_box_id, url) {
        url = backendUrl + "auth-event/" + eid + "/ballot-box/" + ballot_box_id + "/tally-sheet/" + url + "/";
        return $http.delete(url, {});
    }, authmethod.deleteBallotBox = function(eid, url) {
        url = backendUrl + "auth-event/" + eid + "/ballot-box/" + url + "/delete/";
        return $http.delete(url, {});
    }, authmethod.updateUserExtra = function(extra) {
        if (authmethod.isLoggedIn()) return $http.post(backendUrl + "user/extra/", extra);
        var data = {
            then: function(onSuccess, onError) {
                return setTimeout(function() {
                    onError({
                        data: {
                            message: "not-logged-in"
                        }
                    });
                }, 0), data;
            }
        };
        return data;
    }, authmethod.getUserInfo = function(userid) {
        if (authmethod.isLoggedIn()) return void 0 === userid ? $http.get(backendUrl + "user/", {}) : $http.get(backendUrl + "user/%d" % userid, {});
        var data = {
            then: function(onSuccess, onError) {
                return setTimeout(function() {
                    onError({
                        data: {
                            message: "not-logged-in"
                        }
                    });
                }, 0), data;
            }
        };
        return data;
    }, authmethod.ping = function(pingId) {
        if (pingId = pingId || authId, authmethod.isLoggedIn()) return $http.get(backendUrl + "auth-event/" + pingId + "/ping/");
        var data = {
            then: function(onSuccess, onError) {
                return setTimeout(function() {
                    onError({
                        data: {
                            message: "not-logged-in"
                        }
                    });
                }, 0), data;
            }
        };
        return data;
    }, authmethod.getImage = function(ev, uid) {
        return $http.get(backendUrl + "auth-event/" + ev + "/census/img/" + uid + "/");
    }, authmethod.login = function(data, eid) {
        eid = eid || authId;
        return delete data.authevent, $http.post(backendUrl + "auth-event/" + eid + "/authenticate/", data);
    }, authmethod.authenticateOtl = function(data, eid) {
        eid = eid || authId;
        return delete data.authevent, $http.post(backendUrl + "auth-event/" + eid + "/authenticate-otl/", data);
    }, authmethod.censusQuery = function(data, eid) {
        eid = eid || authId;
        return delete data.authevent, $http.post(backendUrl + "auth-event/" + eid + "/census/public-query/", data);
    }, authmethod.resendAuthCode = function(data, eid) {
        return $http.post(backendUrl + "auth-event/" + eid + "/resend_auth_code/", data);
    }, authmethod.editChildrenParent = function(data, eid) {
        return $http.post(backendUrl + "auth-event/" + eid + "/edit-children-parent/", data);
    }, authmethod.getPerm = function(perm, object_type, data) {
        data = {
            permission: perm,
            object_type: object_type,
            object_id: null === data ? data : data + ""
        };
        return $http.post(backendUrl + "get-perms/", data);
    }, authmethod.viewEvent = function(id) {
        return $http.get(backendUrl + "auth-event/" + id + "/");
    }, authmethod.viewEvents = function() {
        return $http.get(backendUrl + "auth-event/");
    }, authmethod.createEvent = function(data) {
        return $http.post(backendUrl + "auth-event/", data);
    }, authmethod.editEvent = function(id, data) {
        return $http.post(backendUrl + "auth-event/" + id + "/", data);
    }, authmethod.addCensus = function(id, d, validation) {
        d = {
            "field-validation": validation = !angular.isDefined(validation) ? "enabled" : validation,
            census: d
        };
        return $http({
            method: "POST",
            url: backendUrl + "auth-event/" + id + "/census/",
            timeout: 1e3 * ConfigService.serverTimeoutSeconds,
            data: d
        });
    }, authmethod.getCensus = function(id, params) {
        return angular.isObject(params) ? $http.get(backendUrl + "auth-event/" + id + "/census/", {
            params: params
        }) : $http.get(backendUrl + "auth-event/" + id + "/census/");
    }, authmethod.getRegisterFields = function(viewEventData) {
        for (var fields = (fields = _.filter(angular.copy(viewEventData.extra_fields), function(item) {
            return !0 !== item.required_when_registered;
        })) || [], i = 0; i < fields.length; i++) if ("captcha" === fields[i].type) {
            var captcha = fields.splice(i, 1);
            fields.push(captcha[0]);
            break;
        }
        return fields;
    }, authmethod.hasOtpCodeField = function(viewEventData) {
        for (var fields = authmethod.getRegisterFields(viewEventData), i = 0; i < fields.length; i++) if ("otp-code" === fields[i].type) return !0;
        return !1;
    }, authmethod.getCensusQueryFields = function(fields) {
        fields = angular.copy(fields.extra_fields);
        return fields = _.filter(fields, function(field) {
            return field.required_on_authentication;
        });
    }, authmethod.getOtlFields = function(fields) {
        fields = angular.copy(fields.extra_fields);
        return fields = _.filter(fields, function(field) {
            return field.match_against_census_on_otl_authentication;
        });
    }, authmethod.getLoginWithCode = function(_viewEventData) {
        return [ {
            name: "__username",
            type: "text",
            required: !0,
            min: 3,
            max: 200,
            required_on_authentication: !0
        }, {
            name: "code",
            type: "code",
            required: !0,
            required_on_authentication: !0
        } ];
    }, authmethod.getLoginFields = function(viewEventData) {
        var fields = authmethod.getRegisterFields(viewEventData), hasOtpCodeField = authmethod.hasOtpCodeField(viewEventData);
        _.contains([ "sms", "email" ], viewEventData.auth_method) ? fields.push({
            name: "code",
            type: "code",
            required: !0,
            required_on_authentication: !0
        }) : (hasOtpCodeField || _.contains([ "sms-otp", "email-otp" ], viewEventData.auth_method)) && fields.push({
            name: "code",
            type: "code",
            required: !0,
            steps: [ 1 ],
            required_on_authentication: !0
        }), fields = _.filter(fields, function(field) {
            return field.required_on_authentication;
        });
        for (var i = 0; i < fields.length; i++) if ("captcha" === fields[i].type) {
            var captcha = fields.splice(i, 1);
            fields.push(captcha[0]);
            break;
        }
        return fields;
    }, authmethod.newCaptcha = function(message) {
        return authmethod.captcha_status = message, $http.get(backendUrl + "captcha/new/", {}).then(function(response) {
            console.log(response.data), null !== response.data.captcha_code ? (authmethod.captcha_code = response.data.captcha_code, 
            authmethod.captcha_image_url = response.data.image_url) : authmethod.captcha_status = "Not found";
        });
    }, authmethod.test = function() {
        return $http.get(backendUrl);
    }, authmethod.electionsIds = function(page, queryIds, ids, page_size) {
        page = page || 1;
        var perms = "edit|view";
        "archived" === (queryIds = queryIds || "all") && (perms = "unarchive|view-archived");
        queryIds = "", queryIds = ids ? "&ids=" + ids.join("|") : "&only_parent_elections=true";
        return page_size && (queryIds += "&n=" + page_size), $http.get(backendUrl + "auth-event/?has_perms=" + perms + queryIds + "&order=-pk&page=" + page);
    }, authmethod.sendAuthCodes = function(data, election, user_ids, auth_method, extra, filter, force_create_otp) {
        var url = backendUrl + "auth-event/" + data + "/census/send_auth/", data = {};
        return angular.isDefined(election) && (data.msg = election.census.config.msg, "email" !== auth_method && "email-otp" !== auth_method || (data.subject = election.census.config.subject, 
        ConfigService.allowHtmlEmails && election.census.config.html_message && (data.html_message = election.census.config.html_message))), 
        angular.isDefined(user_ids) && (data["user-ids"] = user_ids), angular.isDefined(auth_method) && (data["auth-method"] = auth_method), 
        angular.isDefined(force_create_otp) && (data.force_create_otl = force_create_otp), 
        extra && (data.extra = extra), angular.isDefined(filter) && (data.filter = filter), 
        $http.post(url, data);
    }, authmethod.removeUsersIds = function(url, election, data, comment) {
        url = backendUrl + "auth-event/" + url + "/census/delete/", data = {
            "user-ids": data
        };
        return comment && (data.comment = comment), $http.post(url, data);
    }, authmethod.activateUsersIds = function(url, election, user_ids, data) {
        url = backendUrl + "auth-event/" + url + "/census/activate/", data = {
            "user-ids": user_ids,
            comment: data
        };
        return $http.post(url, data);
    }, authmethod.deactivateUsersIds = function(url, election, user_ids, data) {
        url = backendUrl + "auth-event/" + url + "/census/deactivate/", data = {
            "user-ids": user_ids,
            comment: data
        };
        return $http.post(url, data);
    }, authmethod.changeAuthEvent = function(eid, url, data) {
        url = backendUrl + "auth-event/" + eid + "/" + url + "/";
        return void 0 === data && (data = {}), $http.post(url, data);
    }, authmethod.allowTally = function(url) {
        url = backendUrl + "auth-event/" + url + "/allow-tally/";
        return $http.post(url, {});
    }, authmethod.unpublishResults = function(url) {
        url = backendUrl + "auth-event/" + url + "/unpublish-results/";
        return $http.post(url, {});
    }, authmethod.archive = function(url) {
        url = backendUrl + "auth-event/" + url + "/archive/";
        return $http.post(url, {});
    }, authmethod.unarchive = function(url) {
        url = backendUrl + "auth-event/" + url + "/unarchive/";
        return $http.post(url, {});
    }, authmethod.setPublicCandidates = function(url, data) {
        url = backendUrl + "auth-event/" + url + "/set-public-candidates/", data = {
            publicCandidates: data
        };
        return $http.post(url, data);
    }, authmethod.setInsideOtlPeriod = function(url, data) {
        url = backendUrl + "auth-event/" + url + "/set-authenticate-otl-period/", data = {
            set_authenticate_otl_period: data
        };
        return $http.post(url, data);
    }, authmethod.launchTally = function(url, tallyElectionIds, forceTally, data) {
        url = backendUrl + "auth-event/" + url + "/tally-status/", data = {
            children_election_ids: tallyElectionIds,
            force_tally: forceTally,
            mode: data
        };
        return $http.post(url, data);
    };
    var lastRefreshMs = 0;
    return authmethod.refreshAuthToken = function(autheventid) {
        var deferred = $q.defer(), jnow = Date.now();
        if (jnow - lastRefreshMs < 1e3) return deferred.reject("ongoing refresh"), deferred.promise;
        lastRefreshMs = jnow;
        var postfix = "_authevent_" + autheventid;
        if ("hidden" === document.visibilityState) return $cookies.get("auth" + postfix) || $state.go("admin.logout"), 
        deferred.reject("tab not focused"), deferred.promise;
        var now = Date.now(), sessionStartedAtMs = now;
        return authmethod.ping(autheventid).then(function(tokens) {
            var decodedAccessToken = {}, decodedToken = tokens.data["auth-token"];
            decodedToken && (decodedToken = authmethod.decodeToken(decodedToken), decodedAccessToken.expires = new Date(now + 1e3 * decodedToken.expiry_secs_diffs), 
            $cookies.put("auth" + postfix, tokens.data["auth-token"], decodedAccessToken), $cookies.put("isAdmin" + postfix, $cookies.get("isAdmin" + postfix), decodedAccessToken), 
            $cookies.put("userid" + postfix, $cookies.get("userid" + postfix), decodedAccessToken), 
            $cookies.put("userid" + postfix, $cookies.get("userid" + postfix), decodedAccessToken), 
            $cookies.put("user" + postfix, $cookies.get("user" + postfix), decodedAccessToken), 
            authmethod.setAuth($cookies.get("auth" + postfix), $cookies.get("isAdmin" + postfix), autheventid)), 
            angular.isDefined(tokens.data["vote-permission-token"]) ? (decodedAccessToken = tokens.data["vote-permission-token"], 
            decodedAccessToken = authmethod.decodeToken(decodedAccessToken), $window.sessionStorage.setItem("vote_permission_tokens", JSON.stringify([ {
                electionId: autheventid,
                token: tokens.data["vote-permission-token"],
                isFirst: !0,
                sessionStartedAtMs: sessionStartedAtMs,
                sessionEndsAtMs: sessionStartedAtMs + 1e3 * decodedAccessToken.expiry_secs_diff
            } ])), $window.sessionStorage.setItem("show-pdf", !!tokens.data["show-pdf"])) : angular.isDefined(tokens.data["vote-children-info"]) && (tokens = _.chain(tokens.data["vote-children-info"]).map(function(child, index) {
                var decodedAccessToken = child["vote-permission-token"], decodedAccessToken = decodedAccessToken && authmethod.decodeToken(decodedAccessToken) || null;
                return {
                    electionId: child["auth-event-id"],
                    token: child["vote-permission-token"] || null,
                    skipped: !1,
                    voted: !1,
                    numSuccessfulLoginsAllowed: child["num-successful-logins-allowed"],
                    numSuccessfulLogins: child["num-successful-logins"],
                    isFirst: 0 === index,
                    sessionStartedAtMs: sessionStartedAtMs,
                    sessionEndsAtMs: sessionStartedAtMs + 1e3 * (decodedAccessToken && decodedAccessToken.expiry_secs_diff || null)
                };
            }).value(), $window.sessionStorage.setItem("vote_permission_tokens", JSON.stringify(tokens)));
        });
    }, authmethod.getUserDraft = function() {
        if (authmethod.isLoggedIn()) return $http.get(backendUrl + "user/draft/", {});
        var data = {
            then: function(onSuccess, onError) {
                return setTimeout(function() {
                    onError({
                        data: {
                            message: "not-logged-in"
                        }
                    });
                }, 0), data;
            }
        };
        return data;
    }, authmethod.uploadUserDraft = function(draft_data) {
        if (!authmethod.isLoggedIn()) {
            var data = {
                then: function(onSuccess, onError) {
                    return setTimeout(function() {
                        onError({
                            data: {
                                message: "not-logged-in"
                            }
                        });
                    }, 0), data;
                }
            };
            return data;
        }
        draft_data = {
            draft_election: draft_data
        };
        return $http.post(backendUrl + "user/draft/", draft_data);
    }, authmethod.launchSelfTestTask = function() {
        return $http.post(backendUrl + "tasks/launch-self-test/", {});
    }, authmethod.getTasks = function(params) {
        var url = backendUrl + "tasks/";
        return angular.isObject(params) ? $http.get(url, {
            params: params
        }) : $http.get(url);
    }, authmethod.getTask = function(url) {
        url = backendUrl + "tasks/" + url + "/";
        return $http.get(url);
    }, authmethod.cancelTask = function(url) {
        url = backendUrl + "tasks/" + url + "/cancel/";
        return $http.post(url, {});
    }, authmethod.getTurnout = function(url) {
        url = backendUrl + "auth-event/" + url + "/turnout/";
        return $http.get(url);
    }, authmethod;
} ]), angular.module("avRegistration").controller("LoginController", [ "$scope", "$stateParams", function($scope, $stateParams) {
    $scope.event_id = $stateParams.id, $scope.code = $stateParams.code, $scope.email = $stateParams.email, 
    $scope.username = $stateParams.username, $scope.isOpenId = $stateParams.isOpenId, 
    $scope.withCode = $stateParams.withCode, $scope.withAltMethod = $stateParams.withAltMethod, 
    $scope.selectedAltMethod = $stateParams.altmethod, $scope.isOtl = $stateParams.isOtl, 
    $scope.otlSecret = $stateParams.otlSecret;
} ]), angular.module("avRegistration").directive("avLogin", [ "Authmethod", "StateDataService", "$state", "$location", "$cookies", "$window", "$timeout", "ConfigService", "Patterns", function(Authmethod, StateDataService, $state, $location, $cookies, $window, $timeout, ConfigService, Patterns) {
    return {
        restrict: "AE",
        scope: !0,
        link: function(scope, element, attrs) {
            scope.isCensusQuery = attrs.isCensusQuery, scope.isQuery = "true" === $location.search().query, 
            scope.withCode = attrs.withCode, scope.username = attrs.username, scope.isOtl = attrs.isOtl, 
            scope.isOpenId = attrs.isOpenId, scope.otlSecret = attrs.otlSecret, scope.error = null, 
            scope.errorData = null, scope.current_alt_auth_method_id = void 0, scope.alternative_auth_methods = null, 
            scope.csrf = null, attrs.withAltMethod && attrs.selectedAltMethod ? scope.selectedAltMethod = attrs.selectedAltMethod : scope.selectedAltMethod = null, 
            scope.hide_default_login_lookup_field = !1;
            var adminId = ConfigService.freeAuthId + "", autheventid = null;
            function simpleRedirectToLogin() {
                scope.csrf ? $window.location.href = "/election/" + scope.csrf.eventId + "/public/login" : $window.location.href = ConfigService.defaultRoute;
            }
            function getCurrentOidcProviders(auth_event) {
                return auth_event.auth_method_config && auth_event.auth_method_config.config && auth_event.auth_method_config.config.provider_ids ? _.map(auth_event.auth_method_config.config.provider_ids, function(provider_id) {
                    return _.find(auth_event.oidc_providers, function(provider) {
                        return provider.public_info.id === provider_id;
                    });
                }) : [];
            }
            function redirectToLogin() {
                var eventId;
                scope.sendingData || (scope.sendingData = !0, scope.csrf && scope.csrf.eventId ? (eventId = scope.csrf.eventId, 
                Authmethod.viewEvent(eventId).then(function(uri) {
                    var postfix;
                    "ok" === uri.data.status && uri.data.events ? (postfix = "_authevent_" + eventId, 
                    uri = function(postfix) {
                        var eventId = null, redirectUri = null, redirectUri = scope.csrf ? "/election/" + (eventId = scope.csrf.eventId) + "/public/login" : ConfigService.defaultRoute;
                        return scope.oidc_providers = postfix.oidc_providers, scope.current_oidc_providers = getCurrentOidcProviders(postfix), 
                        0 === scope.current_oidc_providers.length || (postfix = _.find(postfix.oidc_providers, function(provider) {
                            return provider.public_info.id === scope.csrf.providerId;
                        })) && postfix.logout_uri && (redirectUri = (redirectUri = postfix.logout_uri).replace("__EVENT_ID__", "" + eventId), 
                        postfix = "_authevent_" + eventId, $cookies.get("id_token_" + postfix) ? redirectUri = redirectUri.replace("__ID_TOKEN__", $cookies.get("id_token_" + postfix)) : -1 < redirectUri.indexOf("__ID_TOKEN__") && (redirectUri = "/election/" + eventId + "/public/login")), 
                        redirectUri;
                    }(uri.data.events), $cookies.remove("id_token_" + postfix), $window.location.href = uri) : simpleRedirectToLogin();
                }, function() {
                    simpleRedirectToLogin();
                })) : $window.location.href = ConfigService.defaultRoute);
            }
            function getURIParameter(paramName2, params) {
                paramName2 = paramName2.replace(/[\[\]]/g, "\\$&"), params = new RegExp("[?&]" + paramName2 + "(=([^&#]*)|&|#|$)").exec(params);
                return params ? params[2] ? decodeURIComponent(params[2].replace(/\+/g, " ")) : "" : null;
            }
            function setOIDCErrorCookie(errorCodename) {
                var options = {};
                ConfigService.authTokenExpirationSeconds && (options.expires = new Date(Date.now() + 1e3 * ConfigService.authTokenExpirationSeconds)), 
                $cookies.put("OIDC_ERROR_COOKIE", angular.toJson({
                    altAuthMethodId: scope.current_alt_auth_method_id,
                    eventId: scope.eventId,
                    errorCodename: errorCodename
                }), options);
            }
            function setError(errorCodename, error) {
                scope.error = error, scope.errorData = angular.toJson({
                    support: ConfigService.contact.email
                }), scope.isOpenId && (setOIDCErrorCookie(errorCodename), redirectToLogin());
            }
            if (scope.oidcError = function() {
                if (!$cookies.get("OIDC_ERROR_COOKIE")) return null;
                var oidcError = angular.fromJson($cookies.get("OIDC_ERROR_COOKIE"));
                return $cookies.remove("OIDC_ERROR_COOKIE"), oidcError;
            }(), scope.oidcError && (scope.selectedAltMethod = scope.oidcError.altAuthMethodId, 
            setError(scope.oidcError.errorCodename, "avRegistration.loginError.openid-connect." + scope.oidcError.errorCodename)), 
            scope.isOpenId) {
                if (!function() {
                    if (!$cookies.get("OIDC_CSRF")) return setOIDCErrorCookie("unexpectedOIDCRedirect"), 
                    void redirectToLogin();
                    var csrf = scope.csrf = angular.fromJson($cookies.get("OIDC_CSRF")), uri = $window.location.search;
                    return $cookies.remove("OIDC_CSRF"), !!csrf && angular.isObject(csrf) && angular.isString(csrf.randomState) && angular.isString(csrf.randomNonce) && angular.isString(csrf.providerId) && angular.isNumber(csrf.created) && angular.isDefined(csrf.altAuthMethodId) && getURIParameter("state", uri) === csrf.randomState && csrf.created - Date.now() < ConfigService.authTokenExpirationSeconds ? 1 : (setOIDCErrorCookie("invalidCsrf"), 
                    void redirectToLogin());
                }()) return;
                autheventid = scope.eventId = attrs.eventId = scope.csrf.eventId, scope.selectedAltMethod = scope.csrf.altAuthMethodId, 
                scope.setLoginOIDC = !0;
            } else autheventid = scope.eventId = attrs.eventId;
            scope.orgName = ConfigService.organization.orgName;
            var autheventCookie = $cookies.get("authevent_" + adminId), authCookie = $cookies.get("auth_authevent_" + adminId);
            function randomStr() {
                var random = sjcl.random.randomWords(64, 0);
                return sjcl.codec.hex.fromBits(random);
            }
            autheventCookie && autheventCookie === adminId && autheventid === adminId && authCookie && ($window.location.href = "/admin/elections"), 
            scope.sendingData = !1, scope.currentFormStep = 0, scope.stateData = StateDataService.getData(), 
            scope.successfulRegistration = scope.stateData.successfulRegistration || !1, scope.signupLink = ConfigService.signupLink, 
            scope.allowUserResend = !1, scope.censusQuery = "not-sent", scope.code = null, attrs.code && 0 < attrs.code.length && (scope.code = attrs.code), 
            scope.email = null, attrs.email && 0 < attrs.email.length && (scope.email = attrs.email), 
            scope.isAdmin = !1, autheventid === adminId && (scope.isAdmin = !0), scope.resendAuthCode = function(field) {
                if (!scope.sendingData && (scope.hasOtpFieldsCode || _.contains([ "email", "email-otp", "sms", "sms-otp" ], scope.method)) && (scope.hasOtpFieldsCode || !(_.contains([ "sms", "sms-otp" ], scope.method) && -1 === scope.telIndex && !scope.hide_default_login_lookup_field || _.contains([ "email", "email-otp" ], scope.method) && -1 === scope.emailIndex && !scope.hide_default_login_lookup_field))) {
                    var stop = !1, data = _.object(_.filter(scope.login_fields, function(element, index) {
                        return element.index = index, void 0 === element.steps || -1 !== element.steps.indexOf(0);
                    }).map(function(element) {
                        var email, pattern;
                        return (_.contains([ "sms", "sms-otp" ], scope.method) && element.index === scope.telIndex && (pattern = "input" + scope.telIndex, 
                        !document.getElementById(pattern) || !angular.element(document.getElementById(pattern)).intlTelInput("isValidNumber")) || _.contains([ "email", "email-otp" ], scope.method) && element.index === scope.emailIndex && (email = element.value, 
                        pattern = Patterns.get("email"), null === email.match(pattern))) && (stop = !0), 
                        [ element.name, element.value ];
                    }));
                    if (!stop) {
                        if (scope.current_alt_auth_method_id && (data.alt_auth_method_id = scope.current_alt_auth_method_id), 
                        field && (field.value = ""), scope.sendingData = !0, scope.skipSendAuthCode) return onAuthCodeSent(), 
                        void (scope.skipSendAuthCode = !1);
                        Authmethod.resendAuthCode(data, autheventid).then(onAuthCodeSent, function(response) {
                            $timeout(scope.sendingDataTimeout, 3e3), setError(null, "avRegistration.errorSendingAuthCode");
                        });
                    }
                }
                function onAuthCodeSent(response) {
                    _.each(scope.login_fields, function(element) {
                        void 0 !== element.steps && -1 === element.steps.indexOf(0) || (element.disabled = !0);
                    }), scope.currentFormStep = 1, setError(null, null), $timeout(scope.sendingDataTimeout, 3e3);
                }
            }, scope.sendingDataTimeout = function() {
                scope.sendingData = !1;
            }, scope.parseAuthToken = function() {
                var message;
                "smart-link" !== scope.method || scope.withCode || (scope.authToken = $location.search()["auth-token"], 
                void 0 !== scope.authToken && (message = "khmac:///".length, message = scope.authToken.substr(message).split("/")[1], 
                scope.user_id = message.split(":")[0]));
            }, scope.checkCensus = function(valid) {
                var data;
                valid && (scope.sendingData || (scope.censusQuery = "querying", data = {
                    captcha_code: Authmethod.captcha_code
                }, _.each(scope.login_fields, function(field) {
                    data[field.name] = field.value;
                }), scope.sendingData = !0, Authmethod.censusQuery(data, autheventid).then(function(response) {
                    scope.sendingData = !1, scope.censusQueryData = response.data, scope.censusQuery = "success";
                }, function(response) {
                    scope.sendingData = !1, scope.censusQuery = "fail";
                })));
            }, scope.otlAuth = function(valid) {
                var data;
                valid && (scope.sendingData || (scope.otlStatus = "querying", data = {
                    captcha_code: Authmethod.captcha_code,
                    __otl_secret: scope.otlSecret
                }, _.each(scope.login_fields, function(field) {
                    data[field.name] = field.value;
                }), scope.sendingData = !0, Authmethod.authenticateOtl(data, autheventid).then(function(response) {
                    scope.sendingData = !1, scope.otpCode = response.data.code, scope.otlResponseData = response.data, 
                    scope.otlStatus = "success";
                }, function(_response) {
                    scope.sendingData = !1, scope.otpCode = void 0, scope.otlResponseData = {}, scope.otlStatus = "fail";
                })));
            }, scope.loginUser = function(valid) {
                if (valid && !scope.sendingData) {
                    var data = {};
                    if (scope.isOpenId) data = function() {
                        var data = {
                            code: getURIParameter("code", $window.location.search),
                            provider_id: scope.csrf.providerId,
                            nonce: scope.csrf.randomNonce
                        }, options = {};
                        ConfigService.authTokenExpirationSeconds && (options.expires = new Date(Date.now() + 1e3 * ConfigService.authTokenExpirationSeconds));
                        var postfix = "_authevent_" + scope.csrf.eventId;
                        return $cookies.put("code_" + postfix, data.code, options), data;
                    }(); else {
                        if (!scope.withCode && (scope.hasOtpFieldsCode || _.contains([ "sms-otp", "email-otp" ], scope.method)) && 0 === scope.currentFormStep) return void scope.resendAuthCode();
                        data.captcha_code = Authmethod.captcha_code;
                        var hasEmptyCode = !1;
                        if (_.each(scope.login_fields, function(field) {
                            angular.isUndefined(field.value) && (data[field.name] = ""), "email" === field.type ? scope.email = field.value : _.contains([ "code", "otp-code" ], field.type) && (angular.isString(field.value) || (hasEmptyCode = !0), 
                            field.value = field.value.trim().replace(/ |\n|\t|-|_/g, "").toUpperCase()), data[field.name] = field.value;
                        }), hasEmptyCode) return;
                        "smart-link" !== scope.method || scope.withCode || (data["auth-token"] = $location.search()["auth-token"]);
                    }
                    scope.current_alt_auth_method_id && (data.alt_auth_method_id = scope.current_alt_auth_method_id), 
                    scope.sendingData = !0, setError(null, null);
                    var sessionStartedAtMs = Date.now();
                    Authmethod.login(data, autheventid).then(function(tokens) {
                        var postfix, options, votingScreenPath, decodedAccessToken;
                        "ok" === tokens.data.status ? (postfix = "_authevent_" + autheventid, options = {}, 
                        decodedAccessToken = tokens.data["auth-token"], votingScreenPath = Authmethod.decodeToken(decodedAccessToken), 
                        options.expires = new Date(sessionStartedAtMs + 1e3 * votingScreenPath.expiry_secs_diff), 
                        $cookies.put("authevent_" + autheventid, autheventid, options), $cookies.put("userid" + postfix, tokens.data.username, options), 
                        $cookies.put("user" + postfix, scope.email || tokens.data.username || tokens.data.email, options), 
                        $cookies.put("auth" + postfix, decodedAccessToken, options), $cookies.put("isAdmin" + postfix, scope.isAdmin, options), 
                        Authmethod.setAuth(decodedAccessToken, scope.isAdmin, autheventid), votingScreenPath = scope.isQuery || scope.base_authevent && scope.base_authevent.force_census_query ? "/eligibility" : "/vote", 
                        scope.isAdmin ? Authmethod.getUserInfo().then(function(response) {
                            var redirectUrl = $window.sessionStorage.getItem("redirect");
                            redirectUrl ? $window.sessionStorage.removeItem("redirect") : redirectUrl = "/admin/elections", 
                            $cookies.put("user" + postfix, response.data.email || scope.email || response.data.username, options), 
                            $window.location.href = redirectUrl;
                        }, function(response) {
                            $window.location.href = "/admin/elections";
                        }) : angular.isDefined(tokens.data["redirect-to-url"]) ? $window.location.href = tokens.data["redirect-to-url"] : angular.isDefined(tokens.data["vote-permission-token"]) ? (decodedAccessToken = tokens.data["vote-permission-token"], 
                        decodedAccessToken = Authmethod.decodeToken(decodedAccessToken), $window.sessionStorage.setItem("vote_permission_tokens", JSON.stringify([ {
                            electionId: autheventid,
                            token: tokens.data["vote-permission-token"],
                            isFirst: !0,
                            sessionStartedAtMs: sessionStartedAtMs,
                            sessionEndsAtMs: sessionStartedAtMs + 1e3 * decodedAccessToken.expiry_secs_diff
                        } ])), $window.sessionStorage.setItem("show-pdf", !!tokens.data["show-pdf"]), $window.location.href = "/booth/" + autheventid + votingScreenPath) : angular.isDefined(tokens.data["vote-children-info"]) ? (tokens = _.chain(tokens.data["vote-children-info"]).map(function(child, index) {
                            var decodedAccessToken = child["vote-permission-token"], decodedAccessToken = decodedAccessToken && Authmethod.decodeToken(decodedAccessToken) || null;
                            return {
                                electionId: child["auth-event-id"],
                                token: child["vote-permission-token"] || null,
                                skipped: !1,
                                voted: !1,
                                numSuccessfulLoginsAllowed: child["num-successful-logins-allowed"],
                                numSuccessfulLogins: child["num-successful-logins"],
                                isFirst: 0 === index,
                                sessionStartedAtMs: sessionStartedAtMs,
                                sessionEndsAtMs: sessionStartedAtMs + 1e3 * (decodedAccessToken && decodedAccessToken.expiry_secs_diff || null)
                            };
                        }).value(), $window.sessionStorage.setItem("vote_permission_tokens", JSON.stringify(tokens)), 
                        $window.location.href = "/booth/" + autheventid + votingScreenPath) : setError("unrecognizedServerResponse", "avRegistration.loginError." + scope.method + ".unrecognizedServerResponse")) : (scope.sendingData = !1, 
                        setError("invalidServerResponse", "avRegistration.loginError." + scope.method + ".invalidServerResponse"));
                    }, function(codename) {
                        scope.sendingData = !1;
                        codename = codename.data.error_codename;
                        setError(codename, "avRegistration.loginError." + scope.method + "." + codename);
                    });
                }
            }, scope.getUriParam = function(paramName2) {
                var params = $window.location.href, paramName2 = paramName2.replace(/[\[\]]/g, "\\$&").replace(/ /g, "%20"), params = new RegExp("[?&]" + paramName2 + "(=([^&#]*)|&|#|$)").exec(params);
                return params ? params[2] ? decodeURIComponent(params[2].replace(/\+/g, " ")) || void 0 : "" : null;
            }, scope.getAltAuthMethodName = function(altAuthMethod) {
                var langCode = $window.i18next.resolvedLanguage;
                return altAuthMethod.public_name_i18n && altAuthMethod.public_name_i18n[langCode] ? altAuthMethod.public_name_i18n[langCode] : altAuthMethod.public_name;
            }, scope.setCurrentAltAuthMethod = function(altAuthMethod, isClick) {
                var authevent = angular.copy(scope.base_authevent);
                if (null === altAuthMethod) return scope.current_alt_auth_method_id = null, scope.isOpenId = scope.isOpenId || "openid-connect" === authevent.auth_method, 
                void scope.apply(authevent);
                altAuthMethod.id !== scope.current_alt_auth_method_id && (isClick && "smart-link" !== scope.selectedAltMethod && "smart-link" === altAuthMethod.auth_method_name || (scope.isOpenId = "openid-connect" === altAuthMethod.auth_method, 
                scope.current_alt_auth_method_id = altAuthMethod.id, authevent.extra_fields = altAuthMethod.extra_fields, 
                authevent.auth_method_config = altAuthMethod.auth_method_config, authevent.auth_method = altAuthMethod.auth_method_name, 
                scope.apply(authevent)));
            }, scope.apply = function(authevent) {
                scope.hasOtpFieldsCode = Authmethod.hasOtpCodeField(authevent), scope.method = authevent.auth_method, 
                scope.oidc_providers = authevent.oidc_providers, scope.current_oidc_providers = getCurrentOidcProviders(authevent), 
                (scope.hasOtpFieldsCode || _.contains([ "sms-otp", "email-otp" ], scope.method)) && (scope.skipSendAuthCode = scope.successfulRegistration), 
                scope.name = authevent.name, scope.parseAuthToken(), scope.registrationAllowed = "open" === authevent.census && (autheventid !== adminId || ConfigService.allowAdminRegistration), 
                scope.isCensusQuery || scope.withCode || scope.isOtl ? scope.withCode ? scope.login_fields = Authmethod.getLoginWithCode(authevent) : scope.isCensusQuery ? scope.login_fields = Authmethod.getCensusQueryFields(authevent) : scope.isOtl && (scope.login_fields = Authmethod.getOtlFields(authevent)) : scope.login_fields = Authmethod.getLoginFields(authevent), 
                scope.login_fields.sort(function(a, b) {
                    var initialFields = [ "tlf", "email", "code", "otp-code" ];
                    return initialFields.includes(a.type) && !initialFields.includes(b.type) ? -1 : !initialFields.includes(a.type) && initialFields.includes(b.type) ? 1 : 0;
                }), scope.hide_default_login_lookup_field = authevent.hide_default_login_lookup_field, 
                scope.telIndex = -1, scope.emailIndex = -1, scope.telField = null, scope.allowUserResend = function() {
                    if (scope.withCode) return !1;
                    var ret = !1, electionsMatch = $location.path(), adminMatch = electionsMatch.match(/^\/admin\//), electionsMatch = electionsMatch.match(/^\/(elections|election)\/([0-9]+)\//);
                    return _.isArray(adminMatch) ? ret = !0 : _.isArray(electionsMatch) && 3 === electionsMatch.length && (ret = _.isObject(authevent.auth_method_config) && _.isObject(authevent.auth_method_config.config) && !0 === authevent.auth_method_config.config.allow_user_resend), 
                    ret;
                }();
                var filledFields = _.map(scope.login_fields, function(el, index) {
                    var uriValue;
                    return scope.stateData[el.name] ? (el.value = scope.stateData[el.name], el.disabled = !0) : (uriValue = scope.getUriParam(el.name), 
                    angular.isString(uriValue) ? (el.value = uriValue, el.disabled = !0) : (el.value = null, 
                    el.disabled = !1)), "email" === el.type ? (null !== scope.email && (el.value = scope.email, 
                    el.disabled = !0, "email-otp" === scope.method && (scope.currentFormStep = 1)), 
                    scope.emailIndex = index) : "code" === el.type && null !== scope.code ? (el.value = scope.code.trim().replace(/ |\n|\t|-|_/g, "").toUpperCase(), 
                    el.disabled = !0) : "tlf" === el.type && "sms" === scope.method ? (null !== scope.email && -1 === scope.email.indexOf("@") && (el.value = scope.email, 
                    el.disabled = !0), scope.telIndex = index + 1, scope.telField = el) : "tlf" === el.type && "sms-otp" === scope.method ? (null !== scope.email && -1 === scope.email.indexOf("@") && (el.value = scope.email, 
                    el.disabled = !0, scope.currentFormStep = 1), scope.telIndex = index + 1, scope.telField = el) : "__username" === el.name && scope.withCode ? (el.value = scope.username, 
                    el.disabled = !0) : "user_id" === el.name && "smart-link" === scope.method && (el.value = scope.user_id, 
                    el.disabled = !0), el;
                });
                0 === scope.currentFormStep && _.contains([ "email-otp", "sms-otp" ], scope.auth_method) && 0 === _.filter(filledFields, function(el) {
                    return null === el.value && !_.contains([ "otp-code", "code" ], el.type);
                }).length && (scope.currentFormStep = 1);
                filledFields = _.filter(filledFields, function(el) {
                    return null !== el.value || "otp-code" === el.type;
                });
                !scope.isOpenId && filledFields.length !== scope.login_fields.length || (scope.isOpenId || scope.isOtl || scope.isCensusQuery || scope.withCode || scope.oidcError || scope.loginUser(!0), 
                scope.setLoginOIDC && scope.loginUser(!0));
            }, scope.view = function(id) {
                Authmethod.viewEvent(id).then(function(altAuthMethod) {
                    "ok" === altAuthMethod.data.status ? (scope.base_authevent = angular.copy(altAuthMethod.data.events), 
                    scope.alternative_auth_methods = scope.base_authevent.alternative_auth_methods, 
                    altAuthMethod = _.find(scope.alternative_auth_methods, function(altAuthMethod) {
                        return altAuthMethod.id === scope.selectedAltMethod;
                    }) || null, scope.setCurrentAltAuthMethod(altAuthMethod)) : document.querySelector(".input-error").style.display = "block";
                }, function(response) {
                    document.querySelector(".input-error").style.display = "block";
                });
            }, scope.view(autheventid), scope.goSignup = function() {
                $state.go("registration.register", {
                    id: autheventid
                });
            }, scope.forgotPassword = function() {
                console.log("forgotPassword");
            }, scope.openidConnectAuth = function(provider) {
                var randomState, options, authURI;
                provider ? (randomState = randomStr(), authURI = randomStr(), options = {}, ConfigService.authTokenExpirationSeconds && (options.expires = new Date(Date.now() + 1e3 * ConfigService.authTokenExpirationSeconds)), 
                $cookies.put("OIDC_CSRF", angular.toJson({
                    randomState: randomState,
                    randomNonce: authURI,
                    altAuthMethodId: scope.current_alt_auth_method_id,
                    created: Date.now(),
                    eventId: scope.eventId,
                    providerId: provider.public_info.id
                }), options), authURI = provider.public_info.authorization_endpoint + "?response_type=code&client_id=" + encodeURIComponent(provider.public_info.client_id) + "&scope=" + encodeURIComponent(provider.public_info.scope) + "&redirect_uri=" + encodeURIComponent($window.location.origin + "/election/login-openid-connect-redirect") + "&state=" + randomState + "&nonce=" + authURI, 
                $window.location.href = authURI) : setError("providerNotFound", "avRegistration.loginError.openid-connect.providerNotFound");
            };
        },
        templateUrl: "avRegistration/login-directive/login-directive.html"
    };
} ]), angular.module("avRegistration").controller("LogoutController", [ "$scope", "$stateParams", "$filter", "ConfigService", "$state", "$cookies", "Authmethod", function($scope, $stateParams, $filter, ConfigService, $state, $cookies, postfix) {
    ConfigService.freeAuthId;
    var authevent = postfix.getAuthevent(), postfix = "_authevent_" + authevent;
    $cookies.put("user" + postfix, ""), $cookies.put("auth" + postfix, ""), $cookies.put("authevent_" + authevent, ""), 
    $cookies.put("userid" + postfix, ""), $cookies.put("isAdmin" + postfix, !1), authevent !== ConfigService.freeAuthId + "" && authevent ? $state.go("registration.login", {
        id: $cookies.get("authevent_" + authevent)
    }) : $state.go("admin.login");
} ]), angular.module("avRegistration").controller("RegisterController", [ "$scope", "$stateParams", "$filter", "ConfigService", function($scope, $stateParams, $filter, ConfigService) {
    $scope.event_id = $stateParams.id, $scope.email = $stateParams.email;
} ]), angular.module("avRegistration").directive("avRegister", [ "Authmethod", "StateDataService", "$parse", "$state", "ConfigService", "$cookies", "$window", "$sce", function(Authmethod, StateDataService, $parse, $state, ConfigService, $cookies, $window, $sce) {
    return {
        restrict: "AE",
        scope: !0,
        link: function(scope, element, attrs) {
            var autheventid = attrs.eventId;
            scope.dnieurl = ConfigService.dnieUrl + autheventid + "/", scope.register = {}, 
            scope.sendingData = !1, scope.admin = !1, scope.error = null, scope.email = null, 
            attrs.email && 0 < attrs.email.length && (scope.email = attrs.email), "admin" in attrs && (scope.admin = !0), 
            scope.getLoginDetails = function(eventId) {
                return scope.admin ? {
                    path: "admin.login_email",
                    data: {
                        email: scope.email
                    }
                } : {
                    path: "election.public.show.login_email",
                    data: {
                        id: eventId,
                        email: scope.email
                    }
                };
            }, scope.signUp = function(valid) {
                var data, details;
                valid && (scope.sendingData = !0, scope.error = null, data = {
                    captcha_code: Authmethod.captcha_code
                }, _.each(scope.register_fields, function(field) {
                    data[field.name] = field.value, ("email" === field.name && _.contains([ "email", "email-otp" ], scope.method) || "tlf" === field.name && _.contains([ "sms", "sms-otp" ], scope.method)) && (scope.email = field.value);
                }), Authmethod.signup(data, autheventid).then(function(response) {
                    details = scope.getLoginDetails(autheventid), "ok" === response.data.status ? (scope.user = response.data.user, 
                    data.successfulRegistration = !0, StateDataService.go(details.path, details.data, data)) : (scope.sendingData = !1, 
                    scope.status = "Not found"), scope.error = response.data.msg || $sce.trustAsHtml($window.i18next.t("avRegistration.invalidRegisterData", {
                        url: $state.href(details.path, details.data)
                    }));
                }, function(response) {
                    details = scope.getLoginDetails(autheventid), scope.sendingData = !1, scope.status = "Registration error: " + response.data.message, 
                    response.data.error_codename && "invalid-dni" === response.data.error_codename ? scope.error = $sce.trustAsHtml($window.i18next.t("avRegistration.invalidRegisterDNI")) : (scope.error = response.data.msg || $sce.trustAsHtml($window.i18next.t("avRegistration.invalidRegisterData", {
                        url: $state.href(details.path, details.data)
                    })), "Invalid captcha" === response.data.msg && Authmethod.newCaptcha());
                }));
            }, scope.goLogin = function(event) {
                console.log("goLogin"), event && (event.preventDefault(), event.stopPropagation()), 
                scope.authevent && (scope.authevent.id === ConfigService.freeAuthId ? $state.go("admin.login") : $state.go("election.public.show.login", {
                    id: scope.authevent.id
                }));
            }, scope.apply = function(authevent) {
                scope.method = authevent.auth_method, scope.name = authevent.name, "open" === (scope.authevent = authevent).census && "openid-connect" !== scope.method || (authevent.id === ConfigService.freeAuthId ? $state.go("admin.login") : $state.go("election.public.show.login", {
                    id: authevent.id
                })), scope.register_fields = Authmethod.getRegisterFields(authevent);
                _.map(scope.register_fields, function(el) {
                    return el.value = null, el.disabled = !1, "email" === el.type && null !== scope.email && (el.value = scope.email, 
                    el.disabled = !0), el;
                });
            }, scope.view = function(id) {
                Authmethod.viewEvent(id).then(function(response) {
                    "ok" === response.data.status ? scope.apply(response.data.events) : (scope.status = "Not found", 
                    document.querySelector(".input-error").style.display = "block");
                }, function(response) {
                    scope.status = "Scan error: " + response.data.message, document.querySelector(".input-error").style.display = "block";
                });
            }, scope.view(autheventid);
        },
        templateUrl: "avRegistration/register-directive/register-directive.html"
    };
} ]), angular.module("avRegistration").factory("Patterns", function() {
    var patterns = {
        get: function(name) {
            return "dni" === name ? /^\d{7,8}[a-zA-Z]{1}$/i : "mail" === name || "email" === name ? /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/ : /.*/;
        }
    };
    return patterns;
}), angular.module("avRegistration").directive("avrField", [ "$state", function($state) {
    return {
        restrict: "AE",
        scope: !0,
        link: function(scope, element, attrs) {
            console.log("type = " + scope.field.type), scope.index = attrs.index;
        },
        templateUrl: "avRegistration/field-directive/field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrEmailField", [ "$state", "Patterns", function($state, Patterns) {
    return {
        restrict: "AE",
        link: function(scope, element, attrs) {
            scope.emailRe = Patterns.get("email");
        },
        scope: !0,
        templateUrl: "avRegistration/fields/email-field-directive/email-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrDateField", [ "$state", "Patterns", function($state, Patterns) {
    return {
        restrict: "AE",
        link: function(scope, element, attrs) {
            var data, dateValue;
            function numberPadStart(str, size) {
                str = "000000000" + str;
                return str.substr(str.length - size);
            }
            scope.years = [], scope.months = [], scope.field = scope.$parent.field, scope.date = null, 
            dateValue = null, dateValue = void 0 === scope.field.value || null === scope.field.value || 0 === scope.field.value.length ? new Date() : (data = scope.field.value.split("-"), 
            new Date(data[0], parseInt(data[1]) - 1, data[2])), scope.date = {
                year: dateValue.getFullYear(),
                month: dateValue.getMonth() + 1,
                day: dateValue.getDate()
            }, scope.getYears = function() {
                for (var initY = new Date().getFullYear(), i = 0, years = [], i = initY; initY - 130 <= i; i--) years.push(i);
                return years;
            }, scope.getMonths = function() {
                for (var i = 0, months = [], i = 1; i <= 12; i++) months.push(i);
                return months;
            }, scope.getDays = function() {
                for (var days = [], i = 0, ndays = new Date(scope.date.year, scope.date.month, 0).getDate(), i = 1; i <= ndays; i++) days.push(i);
                return days;
            }, scope.onChange = function() {
                var monthStr = numberPadStart(scope.date.month, 2), dayStr = numberPadStart(scope.date.day, 2);
                scope.field.value = scope.date.year + "-" + monthStr + "-" + dayStr;
            }, scope.onChange();
        },
        scope: {
            label: "="
        },
        templateUrl: "avRegistration/fields/date-field-directive/date-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrPasswordField", [ "$state", function($state) {
    return {
        restrict: "AE",
        scope: !0,
        templateUrl: "avRegistration/fields/password-field-directive/password-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrTextField", [ "$state", function($state) {
    return {
        restrict: "AE",
        link: function(scope, element, attrs) {
            angular.isUndefined(scope.field.regex) ? scope.re = new RegExp("") : scope.re = new RegExp(scope.field.regex);
        },
        scope: !0,
        templateUrl: "avRegistration/fields/text-field-directive/text-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrDniField", [ "$state", function($state) {
    return {
        restrict: "AE",
        link: function(scope, element, attrs) {
            var dni_re = /^([0-9]{1,8}[A-Z]|[LMXYZ][0-9]{1,7}[A-Z])$/;
            scope.validateDni = function(index) {
                var norm_dni = function(dni) {
                    if (!dni) return "";
                    for (var dni2 = dni.toUpperCase(), dni3 = "", i = 0; i < dni2.lenth; i++) {
                        var char = dni2[i];
                        0 <= "QWERTYUIOPASDFGHJKLZXCVBNM1234567890".indexOf(char) && (dni3 += char);
                    }
                    for (var last_char = "", dni4 = "", j = 0; j < dni3.lenth; j++) {
                        var char2 = dni3[j];
                        "" === last_char || "1234567890".indexOf(last_char), dni4 += char2, last_char = char2;
                    }
                    return dni4;
                }(index);
                if (!norm_dni.match(dni_re)) return !0;
                var prefix = norm_dni.charAt(0), index = "LMXYZ".indexOf(prefix);
                -1 < index && (norm_dni = norm_dni.substr(1), "Y" === prefix ? norm_dni = "1" + norm_dni : "Z" === prefix && (norm_dni = "2" + norm_dni));
                return "TRWAGMYFPDXBNJZSQVHLCKE".charAt(parseInt(norm_dni, 10) % 23) === norm_dni.charAt(norm_dni.length - 1);
            };
        },
        scope: !0,
        templateUrl: "avRegistration/fields/dni-field-directive/dni-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrCodeField", [ "$state", "Plugins", function($state, Plugins) {
    return {
        restrict: "AE",
        scope: !0,
        link: function(scope, element, attrs) {
            scope.codePattern = /[abcdefghjklmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-]{8,9}/;
            var telInput, rand_code = "" + _.random(1e12);
            scope.code_id = "input" + scope.index + rand_code, scope.showResendAuthCode = function() {
                var data = {
                    showUserSendAuthCode: !0
                };
                return Plugins.hook("hide-user-send-auth-code", data), data.showUserSendAuthCode;
            }, _.contains([ "sms", "sms-otp" ], scope.method) && (telInput = angular.element(document.getElementById("input" + scope.telIndex)), 
            scope.isValidTel = telInput.intlTelInput("isValidNumber"), scope.$watch("telField.value", function(newValue, oldValue) {
                scope.isValidTel = telInput.intlTelInput("isValidNumber");
            }, !0));
        },
        templateUrl: "avRegistration/fields/code-field-directive/code-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrTelField", [ "$state", "$timeout", function($state, $timeout) {
    return {
        restrict: "AE",
        scope: !0,
        link: function(scope, element, attrs) {
            scope.tlfPattern = /^[+]?\d{9,14}$/, scope.isValidNumber = !0;
            var ipData = null, ipCallbacks = [];
            $.get("https://ipinfo.io", function() {}, "jsonp").always(function(resp) {
                ipData = resp;
                for (var i = 0; i < ipCallbacks.length; i++) ipCallbacks[i]();
            }), $timeout(function() {
                var telInput = angular.element(document.getElementById("input" + scope.index));
                telInput.intlTelInput({
                    utilsScript: "election/utils.js",
                    separateDialCode: !0,
                    initialCountry: "auto",
                    preferredCountries: [ "es", "gb", "us" ],
                    autoPlaceholder: "aggressive",
                    placeholderNumberType: "MOBILE",
                    geoIpLookup: function(callback) {
                        function applyCountry() {
                            var countryCode = ipData && ipData.country ? ipData.country : "es";
                            callback(countryCode);
                        }
                        ipData ? applyCountry() : ipCallbacks.push(applyCountry);
                    }
                }), _.isString(scope.field.value) && 0 < scope.field.value.length && telInput.intlTelInput("setNumber", scope.field.value);
                telInput.on("keyup change", function() {
                    scope.$evalAsync(function() {
                        var intlNumber = telInput.intlTelInput("getNumber");
                        intlNumber && (scope.field.value = intlNumber), !telInput.intlTelInput("isValidNumber") && 0 < $("#input" + scope.index).val().replace("[ \t\n]", "").length ? (telInput.toggleClass("error", !0), 
                        scope.isValidNumber = !1) : (telInput.toggleClass("error", !1), scope.isValidNumber = !0);
                    });
                });
            });
        },
        templateUrl: "avRegistration/fields/tel-field-directive/tel-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrBoolField", [ "$state", function($state) {
    return {
        restrict: "AE",
        scope: !0,
        templateUrl: "avRegistration/fields/bool-field-directive/bool-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrIntField", [ "$state", function($state) {
    return {
        restrict: "AE",
        link: function(scope, element, attrs) {
            angular.isUndefined(scope.field.regex) ? scope.re = new RegExp("") : scope.re = new RegExp(scope.field.regex);
        },
        scope: !0,
        templateUrl: "avRegistration/fields/int-field-directive/int-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrCaptchaField", [ "Authmethod", "$state", "$interval", function(Authmethod, $state, $interval) {
    return {
        restrict: "AE",
        scope: !0,
        link: function(scope, element, attrs) {
            (scope.authMethod = Authmethod).newCaptcha("");
        },
        templateUrl: "avRegistration/fields/captcha-field-directive/captcha-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrTextareaField", [ "$state", function($state) {
    return {
        restrict: "AE",
        scope: !0,
        templateUrl: "avRegistration/fields/textarea-field-directive/textarea-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrImageField", [ "$state", "$timeout", function($state, $timeout) {
    return {
        restrict: "AE",
        link: function(scope, element, attrs) {
            $timeout(function() {
                $("#image-field").change(function() {
                    var input, FR;
                    (input = this).files && input.files[0] && ((FR = new FileReader()).onload = function(e) {
                        scope.field.value = e.target.result;
                    }, FR.readAsDataURL(input.files[0]));
                });
            }, 0);
        },
        scope: !0,
        templateUrl: "avRegistration/fields/image-field-directive/image-field-directive.html"
    };
} ]), angular.module("avRegistration").factory("Plugins", function() {
    var plugins = {
        plugins: {
            list: []
        }
    };
    return plugins.signals = $.Callbacks("unique"), plugins.hooks = [], plugins.add = function(plugin) {
        plugins.plugins.list.push(plugin);
    }, plugins.clear = function() {
        plugins.plugins.list = [];
    }, plugins.remove = function(plugin) {
        var pluginList = plugins.plugins.list;
        plugins.plugins.list = [], pluginList.forEach(function(pluginFromList) {
            plugin.name !== pluginFromList.name && plugins.plugins.list.push(pluginFromList);
        });
    }, plugins.emit = function(signalName, data) {
        plugins.signals.fire(signalName, data);
    }, plugins.hook = function(hookname, data) {
        for (var i = 0; i < plugins.hooks.length; i++) if (!(0, plugins.hooks[i])(hookname, data)) return !1;
        return !0;
    }, plugins;
}), angular.module("avRegistration").directive("sequentPluginHtml", [ "$compile", "$sce", "$parse", function($compile, $sce, $parse) {
    return function(scope, element, attrs) {
        var parsedHtml = $parse(attrs.ngBindHtml);
        scope.$watch(function() {
            return (parsedHtml(scope) || "").toString();
        }, function() {
            $compile(element, null, -9999)(scope);
        });
    };
} ]), angular.module("avUi", []), jQuery.fn.flash = function(duration) {
    var selector = this;
    angular.isNumber(duration) || (duration = 300), "true" !== selector.attr("is-flashing") && (selector.attr("is-flashing", "true"), 
    selector.addClass("flashing").delay(duration).queue(function() {
        selector.removeClass("flashing").addClass("flashing-out").dequeue();
    }).delay(duration).queue(function() {
        selector.removeClass("flashing flashing-out").dequeue(), selector.attr("is-flashing", "false");
    }));
}, angular.module("avUi").directive("avChildrenElections", [ "ConfigService", function(ConfigService) {
    return {
        restrict: "AE",
        scope: {
            mode: "@",
            callback: "&?",
            parentElectionId: "@?",
            childrenElectionInfo: "="
        },
        link: function(scope, element, attrs) {
            scope.electionsById = {}, scope.selectedElectionId = scope.parentElectionId, scope.hideParent = "true" === attrs.hideParent, 
            _.each(scope.childrenElectionInfo.presentation.categories, function(category) {
                category.hidden = !0, _.each(category.events, function(election) {
                    "checkbox" !== scope.mode && "toggle-and-callback" !== scope.mode || (election.data = election.data || !1, 
                    election.disabled = election.disabled || !1, election.hidden = election.hidden || !1, 
                    election.hidden || (category.hidden = !1));
                });
            }), scope.click = function(election) {
                console.log("click to election.event_id = " + election.event_id), election.disabled ? console.log("election disabled, so ignoring click") : "checkbox" === scope.mode ? election.data = !election.data : "toggle-and-callback" === scope.mode && (scope.selectedElectionId = election.event_id, 
                scope.callback({
                    electionId: election.event_id
                }));
            };
        },
        templateUrl: "avUi/children-elections-directive/children-elections-directive.html"
    };
} ]), angular.module("avUi").directive("avSimpleError", [ "$resource", "$window", function($resource, $window) {
    return {
        restrict: "AE",
        scope: {},
        link: function(scope, element, attrs) {
            scope.updateTitle = function() {
                var title = element.find(".av-simple-error-title"), marginTop = -title.height() - 45, marginLeft = -title.width() / 2;
                title.attr("style", "margin-top: " + marginTop + "px; margin-left: " + marginLeft + "px");
            }, scope.$watch(attrs.title, function() {
                scope.updateTitle();
            });
        },
        transclude: !0,
        templateUrl: "avUi/simple-error-directive/simple-error-directive.html"
    };
} ]), angular.module("avUi").controller("ConfirmModal", [ "$scope", "$modalInstance", "data", function($scope, $modalInstance, data) {
    $scope.data = data, $scope.ok = function() {
        $modalInstance.close(data.closingData);
    }, $scope.cancel = function() {
        $modalInstance.dismiss("cancel");
    };
} ]), angular.module("avUi").service("ShowVersionsModalService", [ "ConfigService", "$modal", "$sce", "$window", function(ConfigService, $modal, $sce, $window) {
    return function() {
        $modal.open({
            templateUrl: "avUi/confirm-modal-controller/confirm-modal-controller.html",
            controller: "ConfirmModal",
            size: "lg",
            resolve: {
                data: function() {
                    var versionList = "<li><strong>" + $window.i18next.t("avCommon.showVersionModal.mainVersion") + " (deployment-tool):</strong> " + ConfigService.mainVersion + "<br><br></li>";
                    _.each(ConfigService.repoVersions, function(repo) {
                        versionList += "<li><strong>" + repo.repoName + ":</strong> " + repo.repoVersion + "</li>";
                    });
                    var body = $sce.trustAsHtml($window.i18next.t("avCommon.showVersionModal.body", {
                        versionList: versionList,
                        interpolation: {
                            escapeValue: !1
                        }
                    }));
                    return {
                        i18n: {
                            header: $window.i18next.t("avCommon.showVersionModal.header"),
                            body: body,
                            confirmButton: $window.i18next.t("avCommon.showVersionModal.confirmButton")
                        },
                        hideCancelButton: !0
                    };
                }
            }
        });
    };
} ]), angular.module("avUi").service("I18nOverride", [ "$i18next", "$rootScope", "$window", function($i18next, $rootScope, $window) {
    return function(overrides, force, languagesConf) {
        force = !!angular.isDefined(force) && force;
        null === overrides || !force && JSON.stringify(overrides) === JSON.stringify($window.i18nOverride) || ($window.i18nOverride = overrides), 
        languagesConf && ($i18next.options.lng = languagesConf.force_default_language ? languagesConf.default_language : $window.i18next.resolvedLanguage, 
        $i18next.options.lngWhitelist = languagesConf.available_languages, $i18next.options.preload = languagesConf.available_languages), 
        console.log("calling $window.i18next.reloadResources().."), $window.i18next.reloadResources($i18next.options.preload, [ "override" ]).then(function() {
            languagesConf && languagesConf.force_default_language && $window.i18next.changeAppLang ? (console.log("reloadResources: successful. force-changing default lang to=" + languagesConf.default_language), 
            $window.i18next.changeAppLang(languagesConf.default_language)) : (console.log("reloadResources: successful. broadcast i18nextLanguageChange signal"), 
            $rootScope.$broadcast("i18nextLanguageChange", $i18next.options.lng));
        });
    };
} ]), angular.module("avUi").directive("avChangeLang", [ "$i18next", "ipCookie", "angularLoad", "amMoment", "$rootScope", "ConfigService", "$window", "Authmethod", function($i18next, ipCookie, angularLoad, amMoment, $rootScope, ConfigService, $window, Authmethod) {
    return {
        restrict: "AE",
        scope: {},
        link: function(scope, element, attrs) {
            scope.deflang = $window.i18next.resolvedLanguage, angular.element("#ng-app").attr("lang", scope.deflang), 
            scope.langs = $window.i18next.options.lngWhitelist;
            var isAdmin = Authmethod.isAdmin();
            element.on("click", function() {
                setTimeout(function() {
                    angular.element("#lang-dropdown-toggle").click();
                }, 0);
            }), $rootScope.$on("i18nextLanguageChange", function(event, languageCode) {
                scope.deflang = languageCode, scope.langs = $i18next.options.lngWhitelist, scope.$apply();
            }), $window.i18next.changeAppLang = scope.changeLang = function(lang) {
                $window.i18next.changeLanguage(lang).then(function() {
                    console.log("changeLang: broadcast i18nextLanguageChange"), $rootScope.$broadcast("i18nextLanguageChange", $window.i18next.resolvedLanguage);
                }), console.log("setting cookie");
                ipCookie("lang", lang, _.extend({
                    expires: 360,
                    path: "/"
                }, ConfigService.i18nextCookieOptions)), scope.deflang = lang, angular.element("#ng-app").attr("lang", scope.deflang), 
                isAdmin && angularLoad.loadScript(ConfigService.base + "/locales/moment/" + lang + ".js").then(function() {
                    amMoment.changeLocale(lang);
                });
            };
        },
        templateUrl: "avUi/change-lang-directive/change-lang-directive.html"
    };
} ]), angular.module("avUi").directive("avbCommonFooter", [ "ConfigService", function(ConfigService) {
    return {
        restrict: "AE",
        scope: {
            float: "="
        },
        link: function(scope, _element, _attrs) {
            scope.configService = ConfigService;
        },
        templateUrl: "avUi/common-footer-directive/common-footer-directive.html"
    };
} ]), angular.module("avUi").directive("avbCommonHeader", [ "ConfigService", "ShowVersionsModalService", function(ConfigService, ShowVersionsModalService) {
    return {
        restrict: "AE",
        scope: {
            hashHelp: "&"
        },
        link: function(scope, _element, attrs) {
            function calculateCountdownPercent() {
                var ratio = (scope.logoutTimeMs - Date.now()) / (scope.logoutTimeMs - scope.countdownStartTimeMs);
                return Math.min(100, Math.round(1e4 * ratio) / 100) + "%";
            }
            function updateProgressBar(percent) {
                var element = $(".logout-bar")[0];
                element && element.style.setProperty("width", percent);
            }
            function updateTimedown() {
                scope.$parent.getSessionEndTime && (scope.logoutTimeMs = scope.$parent.getSessionEndTime()), 
                scope.$parent.getSessionStartTime && (scope.countdownStartTimeMs = scope.$parent.getSessionStartTime(!0)), 
                scope.showCountdown = !0;
                var now = Date.now();
                scope.countdownSecs = Math.round((scope.logoutTimeMs - now) / 1e3), scope.countdownMins = Math.round((scope.logoutTimeMs - now) / 6e4), 
                scope.countdownPercent = calculateCountdownPercent(), updateProgressBar(scope.countdownPercent), 
                scope.$apply(), scope.countdownSecs <= 1 || setTimeout(updateTimedown, 1e3);
            }
            scope.parentElection = scope.$parent.parentElection, scope.election = scope.$parent.election, 
            scope.confirmLogoutModal = scope.$parent.confirmLogoutModal, scope.configService = ConfigService, 
            scope.ballotHash = "false" !== attrs.ballotHash && attrs.ballotHash || !1, scope.isElectionPortal = "true" === attrs.isElectionPortal || !1, 
            scope.buttonsInfo = attrs.buttonsInfo && JSON.parse(attrs.buttonsInfo) || !1, scope.defaultLogo = "/booth/img/Sequent_logo.svg", 
            scope.enableLogOut = function() {
                var election = scope.parentElection || scope.election;
                return !(election && election.presentation && election.presentation.extra_options && election.presentation.extra_options.booth_log_out__disable);
            }, scope.showVersionsModal = ShowVersionsModalService, setTimeout(function() {
                var election, initialTimeMs;
                scope.showCountdown = !1, scope.$parent.isStateCompatibleWithCountdown && !scope.$parent.isStateCompatibleWithCountdown() || (election = scope.parentElection || scope.election, 
                ConfigService.authTokenExpirationSeconds && election && election.presentation && _.isNumber(election.presentation.booth_log_out__countdown_seconds) && (scope.showCountdown = !1, 
                scope.countdownSecs = 0, scope.countdownMins = 0, initialTimeMs = scope.$parent.getSessionStartTime && scope.$parent.getSessionStartTime(!0) || Date.now(), 
                scope.elapsedCountdownMs = 1e3 * (0 < election.presentation.booth_log_out__countdown_seconds ? election.presentation.booth_log_out__countdown_seconds : ConfigService.authTokenExpirationSeconds), 
                scope.$parent.getSessionEndTime ? scope.logoutTimeMs = scope.$parent.getSessionEndTime() : scope.logoutTimeMs = initialTimeMs + 1e3 * ConfigService.authTokenExpirationSeconds, 
                scope.countdownStartTimeMs = scope.logoutTimeMs - scope.elapsedCountdownMs, scope.countdownPercent = calculateCountdownPercent(), 
                updateProgressBar(scope.countdownPercent), scope.isDemo || scope.isPreview || setTimeout(updateTimedown, 0 < election.presentation.booth_log_out__countdown_seconds ? scope.countdownStartTimeMs - Date.now() : 0)));
            }, 0);
        },
        templateUrl: "avUi/common-header-directive/common-header-directive.html"
    };
} ]), angular.module("avUi").directive("avAffixBottom", [ "$window", "$timeout", "$parse", function($window, $timeout, $parse) {
    return {
        restrict: "EAC",
        link: function(scope, iElement, iAttrs) {
            var timeout, instance = {
                affix: !1,
                getIsAffix: null,
                setIsAffix: angular.noop,
                defaultBottomMargin: iElement.css("margin-bottom"),
                forceAffixWidth: parseInt(iAttrs.forceAffixWidth, 10),
                forceAffix: "true" === iAttrs.forceAffix
            };
            function callCheckPos() {
                timeout = $timeout(function() {
                    $timeout.cancel(timeout), function(scope, instance, el) {
                        var affix = !1, elHeight = $(el).actual("height");
                        ($("body").height() + elHeight > window.innerHeight || instance.forceAffixWidth && window.innerWidth < instance.forceAffixWidth || !instance.forceAffixWidth || instance.forceAffix) && (affix = "affix-bottom"), 
                        instance.affixed !== affix && (instance.affix = affix, instance.setIsAffix(scope, affix), 
                        el.removeClass("hidden"), affix ? (el.addClass("affix-bottom"), $(el).parent().css("margin-bottom", elHeight + "px")) : (el.removeClass("affix-bottom"), 
                        $(el).parent().css("margin-bottom", instance.defaultBottomMargin)));
                    }(scope, instance, iElement);
                }, 300);
            }
            0 < iAttrs.avAffixBottom.length && (instance.getIsAffix = $parse(iAttrs.avAffixBottom), 
            instance.setIsAffix = instance.getIsAffix.assign), callCheckPos(), angular.element($window).on("resize", callCheckPos), 
            angular.element(document.body).on("resize", callCheckPos), console.log("iElement NOT resize, height = " + iElement.height()), 
            angular.element(iElement).on("resize", callCheckPos);
        }
    };
} ]), angular.module("avUi").directive("avAutoHeight", [ "$window", "$timeout", function($window, $timeout) {
    return {
        link: function(scope, element, attrs) {
            var promise = null, sibling = function() {
                return element.closest(attrs.parentSelector).find(attrs.siblingSelector);
            }, recalculate = function() {
                promise && $timeout.cancel(promise), promise = $timeout(function() {
                    var height, additionalHeight = 0;
                    attrs.additionalHeight && (additionalHeight = parseInt(attrs.additionalHeight, 10)), 
                    height = sibling().height(), element.css("max-height", height + additionalHeight + "px");
                }, 300);
            };
            scope.$watch(function() {
                return sibling().height();
            }, function(newValue, oldValue) {
                recalculate();
            }), recalculate();
        }
    };
} ]), angular.module("avUi").directive("avAffixTopOffset", [ "$window", "$timeout", "$parse", function($window, $timeout, $parse) {
    return {
        restrict: "EAC",
        link: function(scope, iElement, iAttrs) {
            var instance = {
                affix: !1,
                scrollAffix: null,
                baseOffset: iElement.offset(),
                baseWidth: iElement.width(),
                avAffixTopOffset: parseInt(iAttrs.avAffixTopOffset, 10)
            };
            function callCheckPos() {
                !function(instance, el, options) {
                    var affix = !1, offset = el.offset();
                    instance.affix && $window.pageYOffset + 20 >= instance.scrollAffix || (offset.top - $window.pageYOffset < instance.avAffixTopOffset && (affix = !0), 
                    instance.affix !== affix && (instance.affix = affix, instance.scrollAffix = $window.pageYOffset, 
                    affix ? (el.addClass("affix-top"), el.data("page-offset", $window.pageYOffset), 
                    el.css("position", "fixed"), el.css("float", "none"), el.css("top", Math.floor(instance.avAffixTopOffset) + "px"), 
                    el.css("left", Math.floor(instance.baseOffset.left) + "px"), el.css("width", Math.floor(instance.baseWidth) + "px"), 
                    el.css("z-index", "10"), void 0 !== options.affixPlaceholder && $(options.affixPlaceholder).addClass("affixed")) : (el.removeClass("affix-top"), 
                    el.attr("style", ""), void 0 !== options.affixPlaceholder && $(options.affixPlaceholder).removeClass("affixed"))));
                }(instance, iElement, iAttrs);
            }
            callCheckPos(), angular.element($window).on("scroll", callCheckPos), angular.element($window).on("resize", function() {
                iElement.removeClass("affix-top"), iElement.attr("style", ""), instance.affix = !1, 
                instance.scrollAffix = null, $timeout(function() {
                    instance.baseOffset = iElement.offset(), instance.baseWidth = iElement.width(), 
                    callCheckPos();
                }, 300);
            });
        }
    };
} ]), angular.module("avUi").directive("avAffixTop", [ "$window", "$timeout", function($window, $timeout) {
    function updateMargin(el, options) {
        var height = parseInt(options.minHeight), height = Math.max($(el).height(), angular.isNumber(height) && !isNaN(height) ? height : 0);
        $(options.avAffixTop).css("padding-top", height + "px");
    }
    return {
        restrict: "EAC",
        link: function(scope, iElement, iAttrs) {
            var timeout;
            function updateMarginTimeout() {
                timeout = $timeout(function() {
                    $timeout.cancel(timeout), updateMargin(iElement, iAttrs);
                }, 300);
            }
            updateMargin(iElement, iAttrs), void 0 === iAttrs.minHeight && (iAttrs.minHeight = "20"), 
            updateMarginTimeout(), angular.element(iElement).bind("resize", updateMarginTimeout), 
            angular.element($window).bind("resize", updateMarginTimeout), $(iAttrs.avAffixTop).change(updateMarginTimeout);
        }
    };
} ]), angular.module("avUi").directive("avCollapsing", [ "$window", "$timeout", function($window, $timeout) {
    function select(instance, el, val) {
        val = instance.parentSelector ? el.closest(instance.parentSelector).find(val) : angular.element(val);
        return val;
    }
    function collapseEl(instance, el) {
        return instance.collapseSelector ? select(instance, el, instance.collapseSelector) : angular.element(el);
    }
    return {
        restrict: "EAC",
        link: function(scope, iElement, iAttrs) {
            var timeout, instance = {
                isCollapsed: !1,
                maxHeightSelector: iAttrs.avCollapsing,
                toggleSelector: iAttrs.toggleSelector,
                parentSelector: iAttrs.parentSelector,
                collapseSelector: iAttrs.collapseSelector
            };
            function callCheck() {
                timeout = $timeout(function() {
                    $timeout.cancel(timeout), function(instance, el) {
                        var height, paddingTop, maxHeight = select(instance, el, instance.maxHeightSelector).css("max-height");
                        _.isUndefined(maxHeight) ? console.log("max-height selector not found") : (height = angular.element(el)[0].scrollHeight, 
                        paddingTop = angular.element(el).css("padding-top"), -1 !== maxHeight.indexOf("px") ? (paddingTop = paddingTop && -1 !== paddingTop.indexOf("px") ? parseInt(paddingTop.replace("px", "")) : 0, 
                        (maxHeight = parseInt(maxHeight.replace("px", ""))) < height - paddingTop ? instance.isCollapsed || (instance.isCollapsed = !0, 
                        collapseEl(instance, el).addClass("collapsed"), select(instance, el, instance.toggleSelector).removeClass("hidden in")) : instance.isCollapsed && (instance.isCollapsed = !1, 
                        collapseEl(instance, el).removeClass("collapsed"), select(instance, el, instance.toggleSelector).addClass("hidden"))) : console.log("invalid non-pixels max-height for " + instance.maxHeightSelector));
                    }(instance, iElement);
                }, 500);
            }
            callCheck(), angular.element($window).bind("resize", callCheck), angular.element(iElement).bind("resize", callCheck), 
            angular.element(instance.toggleSelector).bind("click", function() {
                !function(instance, el) {
                    instance.isCollapsed ? (collapseEl(instance, el).removeClass("collapsed"), select(instance, el, instance.toggleSelector).addClass("in")) : (collapseEl(instance, el).addClass("collapsed"), 
                    select(instance, el, instance.toggleSelector).removeClass("in")), instance.isCollapsed = !instance.isCollapsed;
                }(instance, iElement);
            });
        }
    };
} ]), angular.module("avUi").directive("avRecompile", [ "$compile", "$parse", function($compile, $parse) {
    "use strict";
    return {
        scope: !0,
        compile: function(el) {
            var template = function(el) {
                return angular.element("<a></a>").append(el.clone()).html();
            }(el);
            return function(scope, $el, attrs) {
                var stopWatching = scope.$parent.$watch(attrs.avRecompile, function(_new, _old) {
                    var newEl = attrs.hasOwnProperty("useBoolean");
                    (!newEl || _new && "false" !== _new) && (newEl || _new && _new !== _old) && (newEl && $parse(attrs.kcdRecompile).assign(scope.$parent, !1), 
                    newEl = $compile(template)(scope.$parent), $el.replaceWith(newEl), stopWatching(), 
                    scope.$destroy());
                });
            };
        }
    };
} ]), angular.module("avUi").directive("avDebounce", [ "$timeout", function($timeout) {
    return {
        restrict: "A",
        require: "ngModel",
        priority: 99,
        link: function(scope, elm, attr, ngModelCtrl) {
            var debounce;
            "radio" !== attr.type && "checkbox" !== attr.type && (elm.unbind("input"), elm.bind("input", function() {
                $timeout.cancel(debounce), debounce = $timeout(function() {
                    scope.$apply(function() {
                        ngModelCtrl.$setViewValue(elm.val());
                    });
                }, attr.avDebounce || 500);
            }), elm.bind("blur", function() {
                scope.$apply(function() {
                    ngModelCtrl.$setViewValue(elm.val());
                });
            }));
        }
    };
} ]), angular.module("avUi").service("InsideIframeService", function() {
    return function() {
        try {
            return window.self !== window.top;
        } catch (e) {
            return !0;
        }
    };
}), angular.module("avUi").directive("avLoadCss", function() {
    return {
        restrict: "AE",
        scope: {
            css: "="
        },
        link: function(scope, element, _attrs) {
            function updateCss(newValue, oldValue) {
                newValue && "string" == typeof newValue && newValue !== oldValue && element.text(newValue);
            }
            updateCss(scope.css), scope.$watch("css", updateCss);
        }
    };
}), angular.module("avUi").service("PercentVotesService", function() {
    return function(total_votes, question, over, format) {
        function print(num) {
            return "str" === format ? num.toFixed(2) + "%" : num;
        }
        if (void 0 === format && (format = "str"), 0 === total_votes) return print(0);
        var base = question.totals.valid_votes + question.totals.null_votes + question.totals.blank_votes;
        return "over-valid-votes" === (over = null == over ? question.answer_total_votes_percentage : over) || "over-total-valid-votes" === over ? base = question.totals.valid_votes : "over-total-valid-points" === over && void 0 !== question.totals.valid_points && (base = question.totals.valid_points), 
        print(100 * total_votes / base);
    };
}), angular.module("avUi").service("CheckerService", [ "$filter", function($filter) {
    function checker(d) {
        function evalValue(code, $value) {
            return angular.isString(code) ? eval(code) : code;
        }
        function sumStrs(str1, str2) {
            var ret = "";
            return angular.isString(str1) && (ret = str1), angular.isString(str2) && (ret += str2), 
            ret;
        }
        function error(errorKey, errorData, postfix) {
            angular.extend(errorData, d.errorData), d.onError(_.reduce([ d.prefix, errorKey, postfix ], sumStrs, ""), errorData);
        }
        angular.isUndefined(d.errorData) && (d.errorData = {});
        var ret = _.every(d.checks, function(item) {
            var errorData, min, max, itemMin, itemMax, data, extra, prefix, pass = !0, dataToCheck = angular.isDefined(item.key) ? d.data[item.key] : d.data;
            return "is-int" === item.check ? (pass = angular.isNumber(dataToCheck, item.postfix)) || error(item.check, {
                key: item.key
            }, item.postfix) : "is-array" === item.check ? (pass = angular.isArray(dataToCheck, item.postfix)) || error(item.check, {
                key: item.key
            }, item.postfix) : "lambda" === item.check ? item.validator(dataToCheck) || (errorData = {
                key: item.key
            }, angular.isUndefined(item.appendOnErrorLambda) || (errorData = item.appendOnErrorLambda(dataToCheck)), 
            _.isObject(item.append) && _.isString(item.append.key) && !_.isUndefined(item.append.value) && (errorData[item.append.key] = evalValue(item.append.value, item)), 
            error(item.check, errorData, item.postfix)) : "is-string-if-defined" === item.check ? (pass = angular.isUndefined(dataToCheck) || angular.isString(dataToCheck, item.postfix)) || error(item.check, {
                key: item.key
            }, item.postfix) : "array-length-if-defined" === item.check ? angular.isDefined(dataToCheck) && (itemMin = evalValue(item.min, d.data), 
            itemMax = evalValue(item.max, d.data), (angular.isArray(dataToCheck) || angular.isString(dataToCheck)) && (min = angular.isUndefined(item.min) || dataToCheck.length >= itemMin, 
            max = angular.isUndefined(item.max) || dataToCheck.length <= itemMax, pass = min && max, 
            min || error("array-length-min", {
                key: item.key,
                min: itemMin,
                num: dataToCheck.length
            }, item.postfix), max || error("array-length-max", {
                key: item.key,
                max: itemMax,
                num: dataToCheck.length
            }, item.postfix))) : "is-string" === item.check ? (pass = angular.isString(dataToCheck, item.postfix)) || error(item.check, {
                key: item.key
            }, item.postfix) : "array-length" === item.check ? (itemMin = evalValue(item.min, d.data), 
            itemMax = evalValue(item.max, d.data), (angular.isArray(dataToCheck) || angular.isString(dataToCheck)) && (min = angular.isUndefined(item.min) || dataToCheck.length >= itemMin, 
            max = angular.isUndefined(item.max) || dataToCheck.length <= itemMax, pass = min && max, 
            min || error("array-length-min", {
                key: item.key,
                min: itemMin,
                num: dataToCheck.length
            }, item.postfix), max || error("array-length-max", {
                key: item.key,
                max: itemMax,
                num: dataToCheck.length
            }, item.postfix))) : "int-size" === item.check ? (itemMin = evalValue(item.min, d.data), 
            itemMax = evalValue(item.max, d.data), min = angular.isUndefined(item.min) || itemMin <= dataToCheck, 
            max = angular.isUndefined(item.max) || dataToCheck <= itemMax, pass = min && max, 
            min || error("int-size-min", {
                key: item.key,
                min: itemMin,
                value: dataToCheck
            }, item.postfix), max || error("int-size-max", {
                key: item.key,
                max: itemMax,
                value: dataToCheck
            }, item.postfix)) : "group-chain" === item.check ? pass = _.all(_.map(item.checks, function(check) {
                return checker({
                    data: d.data,
                    errorData: d.errorData,
                    onError: d.onError,
                    checks: [ check ],
                    prefix: sumStrs(d.prefix, item.prefix)
                });
            })) : "array-key-group-chain" === item.check ? pass = _.every(dataToCheck, function(data, index) {
                var extra = {}, prefix = "";
                return angular.isString(d.prefix) && (prefix = d.prefix), angular.isString(item.prefix) && (prefix += item.prefix), 
                extra.prefix = prefix, extra[item.append.key] = evalValue(item.append.value, data), 
                checker({
                    data: data,
                    errorData: angular.extend({}, d.errorData, extra),
                    onError: d.onError,
                    checks: item.checks,
                    prefix: sumStrs(d.prefix, item.prefix)
                });
            }) : "array-group-chain" === item.check ? pass = _.every(d.data, function(data, index) {
                var extra = {};
                return extra[item.append.key] = evalValue(item.append.value, data), checker({
                    data: data,
                    errorData: angular.extend({}, d.errorData, extra),
                    onError: d.onError,
                    checks: item.checks,
                    prefix: sumStrs(d.prefix, item.prefix)
                });
            }) : "array-group" === item.check ? pass = _.contains(_.map(d.data, function(data, index) {
                var extra = {};
                return extra[item.append.key] = evalValue(item.append.value, data), checker({
                    data: data,
                    errorData: angular.extend({}, d.errorData, extra),
                    onError: d.onError,
                    checks: item.checks,
                    prefix: sumStrs(d.prefix, item.prefix)
                });
            }), !0) : "object-key-chain" === item.check && (pass = _.isString(item.key) && _.isObject(dataToCheck)) && (data = dataToCheck, 
            (extra = {})[item.append.key] = evalValue(item.append.value, data), prefix = "", 
            angular.isString(d.prefix) && (prefix += d.prefix), angular.isString(item.prefix) && (prefix += item.prefix), 
            pass = _.every(item.checks, function(check, index) {
                return checker({
                    data: data,
                    errorData: angular.extend({}, d.errorData, extra),
                    onError: d.onError,
                    checks: [ check ],
                    prefix: prefix
                });
            })), !(!pass && "chain" === d.data.groupType);
        });
        return ret;
    }
    return checker;
} ]), angular.module("avUi").factory("ElectionCreation", function() {
    var service = {
        generateAuthapiRequest: function(el) {
            el.census.config.subject && !_.contains([ "email", "email-otp" ], el.census.auth_method) && delete el.census.config.subject;
            var d = el.census.config["authentication-action"];
            "vote" === d.mode && (d["mode-config"] = null);
            d = {
                auth_method: el.census.auth_method,
                oidc_providers: el.census.oidc_providers,
                has_ballot_boxes: el.census.has_ballot_boxes,
                support_otl_enabled: el.census.support_otl_enabled || !1,
                census: el.census.census,
                auth_method_config: el.census.config,
                extra_fields: [],
                admin_fields: [],
                num_successful_logins_allowed: el.num_successful_logins_allowed,
                scheduled_events: el.scheduled_events || null,
                allow_public_census_query: el.allow_public_census_query,
                force_census_query: el.force_census_query || !1,
                hide_default_login_lookup_field: el.hide_default_login_lookup_field,
                parent_id: el.parent_id || null,
                children_election_info: el.children_election_info || null,
                alternative_auth_methods: el.census.alternative_auth_methods || null
            };
            return el.id && (d.id = el.id), d.admin_fields = _.filter(el.census.admin_fields, function(af) {
                return !0;
            }), d.extra_fields = _.filter(el.census.extra_fields, function(ef) {
                return delete ef.disabled, delete ef.must, delete ef.value, angular.isUndefined(ef.regex) || _.contains([ "int", "text" ], ef.type) && 0 !== $.trim(ef.regex).length || delete ef.regex, 
                _.contains([ "bool", "captcha" ], ef.type) ? (delete ef.min, delete ef.max) : (ef.min && (ef.min = parseInt(ef.min)), 
                ef.max && (ef.max = parseInt(ef.max))), !0;
            }), d;
        },
        generateAuthapiResponse: function(election) {
            election = service.generateAuthapiRequest(election);
            return election.users = 0, election.tally_status = "notstarted", election.allow_public_census_query = !1, 
            election.created = "2022-12-05T15:22:34.862203%2B00:00", election.based_in = election.based_in || null, 
            election.hide_default_login_lookup_field = election.hide_default_login_lookup_field || !1, 
            election.auth_method_config.config = {
                allow_user_resend: election.auth_method_config.allow_user_resend
            }, election.openid_connect_providers = [], election.inside_authenticate_otl_period = !1, 
            election;
        },
        generateBallotBoxRequest: function(el) {
            el = angular.copy(el);
            return "object" == typeof el.extra_data && (el.extra_data = JSON.stringify(el.extra_data)), 
            "object" == typeof el.tallyPipesConfig && (el.tallyPipesConfig = JSON.stringify(el.tallyPipesConfig)), 
            "object" == typeof el.ballotBoxesResultsConfig && (el.ballotBoxesResultsConfig = JSON.stringify(el.ballotBoxesResultsConfig)), 
            _.each(el.questions, function(q) {
                _.each(q.answers, function(answer) {
                    answer.urls = _.filter(answer.urls, function(url) {
                        return 0 < $.trim(url.url).length;
                    });
                });
            }), el;
        },
        generateBallotBoxResponse: function(election) {
            election = service.generateBallotBoxRequest(election);
            return election.ballotBoxesResultsConfig = election.ballotBoxesResultsConfig || "", 
            election.virtual = election.virtual || !1, election.tally_allowed = !1, election.publicCandidates = !0, 
            election.virtualSubelections = election.virtualSubelections || [], election.logo_url = election.logo_url || "", 
            {
                id: election.id,
                configuration: election,
                state: "started",
                pks: JSON.stringify(election.questions.map(function(q) {
                    return {
                        q: "24792774508736884642868649594982829646677044143456685966902090450389126928108831401260556520412635107010557472033959413182721740344201744439332485685961403243832055703485006331622597516714353334475003356107214415133930521931501335636267863542365051534250347372371067531454567272385185891163945756520887249904654258635354225185183883072436706698802915430665330310171817147030511296815138402638418197652072758525915640803066679883309656829521003317945389314422254112846989412579196000319352105328237736727287933765675623872956765501985588170384171812463052893055840132089533980513123557770728491280124996262883108653723",
                        p: "49585549017473769285737299189965659293354088286913371933804180900778253856217662802521113040825270214021114944067918826365443480688403488878664971371922806487664111406970012663245195033428706668950006712214428830267861043863002671272535727084730103068500694744742135062909134544770371782327891513041774499809308517270708450370367766144873413397605830861330660620343634294061022593630276805276836395304145517051831281606133359766619313659042006635890778628844508225693978825158392000638704210656475473454575867531351247745913531003971176340768343624926105786111680264179067961026247115541456982560249992525766217307447",
                        y: "25233303610624276354982811986201834016697399044876854448496917180808794460600684041443897755355520203095802059616029587815193698920031231714345315925211168639624595654625128533802897292140868582328656520616332091010467955507834092620045939069623671407818190171090021825044623127204061232697474129851550188729946673890631720197446903235998242798036758238763406311552128366413931805575611209227161344639186615808279023879377699069225460149170905910146022296229949546176735955646970920639173343909852697354526383408023054713403757933275765703706664300550788437833505997522376371433614613665995482912523477014539823187236",
                        g: "27257469383433468307851821232336029008797963446516266868278476598991619799718416119050669032044861635977216445034054414149795443466616532657735624478207460577590891079795564114912418442396707864995938563067755479563850474870766067031326511471051504594777928264027177308453446787478587442663554203039337902473879502917292403539820877956251471612701203572143972352943753791062696757791667318486190154610777475721752749567975013100844032853600120195534259802017090281900264646220781224136443700521419393245058421718455034330177739612895494553069450438317893406027741045575821283411891535713793639123109933196544017309147"
                    };
                })),
                tallyPipesConfig: election.tallyPipesConfig,
                ballotBoxesResultsConfig: election.ballotBoxesResultsConfig,
                virtual: election.virtual,
                tallyAllowed: !1,
                publicCandidates: !0,
                logo_url: election.logo_url,
                trusteeKeysState: []
            };
        }
    };
    return service;
}), angular.module("avUi").service("AddDotsToIntService", function() {
    return function(number, fixedDigits) {
        var number_str = ((number = angular.isNumber(fixedDigits) && 0 <= fixedDigits ? number.toFixed(parseInt(fixedDigits)) : number) + "").replace(".", ","), ret = "", commaPos = number_str.length;
        -1 !== number_str.indexOf(",") && (commaPos = number_str.indexOf(","));
        for (var i = 0; i < commaPos; i++) {
            var reverse = commaPos - i;
            reverse % 3 == 0 && 0 < reverse && 0 < i && (ret += "."), ret += number_str[i];
        }
        return ret + number_str.substr(commaPos, number_str.length);
    };
}), angular.module("avUi").service("EndsWithService", function() {
    return function(originString, searchString) {
        if (!angular.isString(originString) || !angular.isString(searchString)) return !1;
        var lastIndex = originString.indexOf(searchString);
        return -1 !== lastIndex && lastIndex === originString.length - searchString.length;
    };
}), angular.module("avUi").service("StateDataService", [ "$state", function($state) {
    var data = {};
    return {
        go: function(path, stateData, newData) {
            data = angular.copy(newData), $state.go(path, stateData);
        },
        getData: function() {
            return data;
        }
    };
} ]), angular.module("avUi").directive("avScrollToBottom", [ "$timeout", function($timeout) {
    return {
        restrict: "A",
        link: function(scope, element, attrs) {
            scope.$watch(function() {
                return element.children().length;
            }, function() {
                element.animate({
                    scrollTop: element.prop("scrollHeight")
                }, 300);
            });
        }
    };
} ]), angular.module("avUi").filter("addTargetBlank", function() {
    return function(tree) {
        tree = angular.element("<div>" + tree + "</div>");
        return tree.find("a").attr("target", "_blank"), angular.element("<div>").append(tree).html();
    };
}), angular.module("avUi").filter("htmlToText", [ "$sanitize", function($sanitize) {
    return function(sanitizedText) {
        sanitizedText = $sanitize(sanitizedText);
        return angular.element("<div>" + sanitizedText + "</div>").text();
    };
} ]), angular.module("avUi").config([ "$provide", function($provide) {
    $provide.decorator("ngModelDirective", [ "$delegate", function($delegate) {
        var ngModel = $delegate[0], controller = ngModel.controller;
        return ngModel.controller = [ "$scope", "$element", "$attrs", "$injector", function(scope, element, attrs, $injector) {
            var $interpolate = $injector.get("$interpolate");
            attrs.$set("name", $interpolate(attrs.name || "")(scope)), $injector.invoke(controller, Object.setPrototypeOf(this, controller.prototype), {
                $scope: scope,
                $element: element,
                $attrs: attrs
            });
        } ], $delegate;
    } ]), $provide.decorator("formDirective", [ "$delegate", function($delegate) {
        var form = $delegate[0], controller = form.controller;
        return form.controller = [ "$scope", "$element", "$attrs", "$injector", function(scope, element, attrs, $injector) {
            var $interpolate = $injector.get("$interpolate");
            attrs.$set("name", $interpolate(attrs.name || attrs.ngForm || "")(scope)), $injector.invoke(controller, Object.setPrototypeOf(this, controller.prototype), {
                $scope: scope,
                $element: element,
                $attrs: attrs
            });
        } ], $delegate;
    } ]);
} ]), angular.module("avUi").controller("DocumentationUiController", [ "$state", "$stateParams", "$http", "$scope", "$sce", "$i18next", "ConfigService", "InsideIframeService", "Authmethod", function($state, $stateParams, $http, $scope, $sce, $i18next, ConfigService, InsideIframeService, Authmethod) {
    $scope.inside_iframe = InsideIframeService(), $scope.documentation = ConfigService.documentation, 
    $scope.documentation.security_contact = ConfigService.legal.security_contact, $scope.documentation_html_include = $sce.trustAsHtml(ConfigService.documentation_html_include), 
    $scope.auths_url = "/election/" + $stateParams.id + "/public/authorities", $scope.election_id = $stateParams.id + "", 
    Authmethod.viewEvent($stateParams.id).then(function(response) {
        "ok" === response.data.status && ($scope.authEvent = response.data.events);
    });
} ]), angular.module("avUi").directive("documentationDirective", function() {
    return {
        restrict: "AE",
        scope: {
            extra: "="
        },
        templateUrl: "avUi/documentation-directive/documentation-directive.html",
        controller: "DocumentationUiController"
    };
}), angular.module("avUi").directive("avFoot", [ "ConfigService", function(ConfigService) {
    return {
        restrict: "AE",
        scope: {},
        link: function(scope, element, attrs) {
            scope.contact = ConfigService.contact, scope.social = ConfigService.social, scope.technology = ConfigService.technology, 
            scope.legal = ConfigService.legal, scope.organization = ConfigService.organization;
        },
        templateUrl: "avUi/foot-directive/foot-directive.html"
    };
} ]), angular.module("avUi").filter("customI18n", function() {
    function customI18nFilter(data, key) {
        var lang = window.i18next.resolvedLanguage, value = "";
        return value = _.isString(key) && _.isObject(data) && _.isString(lang) ? data[key + "_i18n"] && data[key + "_i18n"][lang] || data[key] || value : value;
    }
    return customI18nFilter.$stateful = !0, customI18nFilter;
}), angular.module("common-ui", [ "ui.bootstrap", "ui.utils", "ui.router", "ngAnimate", "ngResource", "ngCookies", "ipCookie", "ngSanitize", "infinite-scroll", "angularMoment", "SequentConfig", "jm.i18next", "avRegistration", "avUi", "avTest", "angularFileUpload", "dndLists", "angularLoad", "ng-autofocus" ]), 
angular.module("common-ui").run([ "$http", "$rootScope", function($http, $rootScope) {
    $rootScope.safeApply = function(fn) {
        var phase = $rootScope.$$phase;
        "$apply" === phase || "$digest" === phase ? fn && "function" == typeof fn && fn() : this.$apply(fn);
    }, $rootScope.$on("$stateChangeStart", function(event, toState, toParams, fromState, fromParams) {
        console.log("change start from " + fromState.name + " to " + toState.name), $("#angular-preloading").show();
    }), $rootScope.$on("$stateChangeSuccess", function(event, toState, toParams, fromState, fromParams) {
        console.log("change success"), $("#angular-preloading").hide();
    });
} ]), angular.module("common-ui").directive("ngSpaceClick", [ "$timeout", function($timeout) {
    return function(scope, element, attrs) {
        element.bind("keydown", function(event) {
            switch (event.which) {
              case 13:
              case 32:
                $timeout(function() {
                    event.currentTarget.click();
                }, 0), event.stopPropagation();
            }
        });
    };
} ]), angular.module("common-ui").directive("ngEnter", function() {
    return function(scope, element, attrs) {
        element.bind("keydown keypress", function(event) {
            13 === event.which && (scope.$apply(function() {
                scope.$eval(attrs.ngEnter);
            }), event.preventDefault());
        });
    };
}), angular.module("common-ui").filter("truncate", function() {
    return function(text, length, end) {
        return isNaN(length) && (length = 10), void 0 === end && (end = "..."), text.length <= length || text.length - end.length <= length ? text : String(text).substring(0, length - end.length) + end;
    };
}), SequentConfigData.browserUpdate) try {
    document.addEventListener("DOMContentLoaded", $buo_f, !1);
} catch (e) {
    window.attachEvent("onload", $buo_f);
}

angular.module("avTest", []), angular.module("avTest").controller("UnitTestE2EController", [ "$scope", "$location", "ConfigService", function($scope, $location, ConfigService) {
    ConfigService.debug && ($scope.html = $location.search().html, console.log($location.search()));
} ]), angular.module("common-ui").run([ "$templateCache", function($templateCache) {
    "use strict";
    $templateCache.put("avRegistration/error.html", '<div av-simple-error><p ng-i18next="avRegistration.errorRegistration"></p></div>'), 
    $templateCache.put("avRegistration/field-directive/field-directive.html", '<div ng-switch="field.type"><div avr-email-field ng-switch-when="email"></div><div avr-password-field ng-switch-when="password"></div><div avr-code-field ng-switch-when="code"></div><div avr-text-field ng-switch-when="text"></div><div avr-dni-field ng-switch-when="dni"></div><div avr-date-field ng-switch-when="date"></div><div avr-tel-field ng-switch-when="tlf"></div><div avr-int-field ng-switch-when="int"></div><div avr-bool-field ng-switch-when="bool"></div><div avr-captcha-field ng-switch-when="captcha"></div><div avr-textarea-field ng-switch-when="textarea"></div><div avr-image-field ng-switch-when="image"></div></div>'), 
    $templateCache.put("avRegistration/fields/bool-field-directive/bool-field-directive.html", '<div class="form-group"><label><input type="checkbox" class="form-control" aria-labeledby="label-{{index}}Text" id="{{index}}Text" ng-model="field.value" ng-disabled="field.disabled" tabindex="0" ng-required="{{field.required}}"></label><div class="bool-text-content"><label class="text-left" for="{{index}}Text" id="label-{{index}}Text"><span ng-bind-html="(field | customI18n : \'name\') | addTargetBlank"></span></label><p class="help-block" ng-if="field.help" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><div class="input-error"></div></div></div>'), 
    $templateCache.put("avRegistration/fields/captcha-field-directive/captcha-field-directive.html", '<div class="form-group"><div class="col-sm-8 col-sm-offset-4"><img ng-src="{{authMethod.captcha_image_url}}" style="width:161px;height:65px"></div><label id="label-{{index}}Text" for="{{index}}Text"><span>{{field | customI18n : \'name\'}}</span></label><div><input type="text" class="form-control" aria-labeledby="label-{{index}}Text" id="{{index}}Text" minlength="{{field.min}}" maxlength="{{field.max}}" ng-model="field.value" ng-disabled="field.disabled" autocomplete="off" tabindex="0" required><p class="help-block" ng-if="field.help" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><div class="input-error">{{authMethod.captcha_status}}</div></div></div>'), 
    $templateCache.put("avRegistration/fields/code-field-directive/code-field-directive.html", '<div class="form-group"><label id="{{code_id}}-code" for="{{code_id}}" ng-i18next="avRegistration.codeLabel"></label><div><input type="text" class="form-control" aria-labeledby="{{code_id}}-code" id="{{code_id}}" ng-model="field.value" ng-disabled="field.disabled" tabindex="0" autocomplete="off" ng-class="{\'filled\': form[code_id].$viewValue.length > 0}" minlength="8" maxlength="9" ng-pattern="codePattern" name="{{code_id}}" ng-i18next="[placeholder]avRegistration.codePlaceholder" required><p class="help-block" ng-if="!field.help || field.help.length === 0" ng-i18next="avRegistration.codeHelp"></p><p class="help-block" ng-if="!!field.help && field.help.length > 0" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><p class="help-block code-help" ng-if="allowUserResend && showResendAuthCode() && !sendingData && ((method !== \'sms\' && method !== \'sms-otp\') || isValidTel)"><span><b ng-i18next="avRegistration.noCodeReceivedQuestion"></b> <a ng-click="resendAuthCode(field)" ng-i18next="avRegistration.sendCodeAgain"></a> <span></span></span></p><div class="input-error"></div></div></div>'), 
    $templateCache.put("avRegistration/fields/date-field-directive/date-field-directive.html", '<div class="form-group"><label ng-if="!label">{{field | customI18n : \'name\'}}</label> <label ng-if="label" ng-bind="label"></label><div><select aria-label="{{field.name}}-year" ng-model="date.year" ng-change="onChange()" ng-disabled="field.disabled"><option ng-selected="date.year == item" ng-repeat="item in getYears()" ng-value="item">{{item}}</option></select> <select aria-label="{{field.name}}-month" ng-model="date.month" ng-change="onChange()" ng-disabled="field.disabled"><option ng-selected="date.month == item" ng-repeat="item in getMonths()" ng-value="item">{{item}}</option></select> <select aria-label="{{field.name}}-day" ng-model="date.day" ng-change="onChange()" ng-disabled="field.disabled"><option ng-selected="date.day == item" ng-repeat="item in getDays()" ng-value="item">{{item}}</option></select><p class="help-block" ng-if="field.help" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p></div></div>'), 
    $templateCache.put("avRegistration/fields/dni-field-directive/dni-field-directive.html", '<ng-form name="fieldForm"><div class="form-group" ng-class="{\'has-error\': fieldForm.input.$dirty && fieldForm.input.$invalid}"><label id="label-input{{index}}" for="input{{index}}"><span>{{field | customI18n : \'name\'}}</span></label><div><input type="text" id="input{{index}}" aria-labeledby="label-input{{index}}" class="form-control" minlength="{{field.min}}" maxlength="{{field.max}}" ng-model="field.value" ng-model-options="{debounce: 500}" ng-disabled="field.disabled" tabindex="0" autocomplete="off" ui-validate="{dni: \'validateDni($value)\'}" ng-required="{{field.required}}"><p class="help-block" ng-if="!field.help || field.help.length === 0" ng-i18next="avRegistration.dniHelp"></p><p class="help-block" ng-if="!!field.help && field.help.length > 0" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><div class="input-error"><span class="error text-brand-danger" ng-show="fieldForm.input.$dirty && fieldForm.input.$invalid" ng-i18next="avRegistration.invalidDni"></span></div></div></div></ng-form>'), 
    $templateCache.put("avRegistration/fields/email-field-directive/email-field-directive.html", '<div class="form-group" ng-class="{true: \'has-error\',false: \'is-required\'}[form.emailText.$dirty && form.emailText.$invalid]"><label for="emailText" id="label-emailText" ng-i18next="avRegistration.emailLabel"></label><div><input type="text" class="form-control" ng-model="field.value" name="emailText" id="emailText" aria-labelledby="label-emailText" ng-i18next="[placeholder]avRegistration.emailPlaceholder" tabindex="0" autocomplete="off" ng-pattern="emailRe" required ng-disabled="field.disabled"><p class="text-warning" ng-if="\'email-otp\' === method && (!field.help || field.help.length === 0)" ng-i18next="avRegistration.otpHelp"></p><p class="help-block" ng-if="!!field.help && field.help.length > 0" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><div class="input-error"><small class="error text-danger" role="alert" ng-show="form.emailText.$dirty && form.emailText.$invalid" ng-i18next="avRegistration.emailError"></small></div></div></div>'), 
    $templateCache.put("avRegistration/fields/image-field-directive/image-field-directive.html", '<ng-form name="fieldForm"><div class="form-group" ng-class="{\'has-error\': fieldForm.input.$dirty && fieldForm.input.$invalid}"><label id="label-image-field" for="image-field"><span>{{field | customI18n : \'name\'}}</span></label><div><input type="file" name="image" id="image-field" aria-labeledby="label-image-field" class="form-control" ng-disabled="field.disabled" tabindex="0" ng-required="{{field.required}}"><p class="help-block" ng-if="!field.help || field.help.length === 0" ng-i18next="avRegistration.imageHelp"></p><p class="help-block" ng-if="!!field.help && field.help.length > 0" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><div class="input-error"><span class="error text-brand-danger" role="alert" ng-show="fieldForm.input.$dirty && fieldForm.input.$invalid" ng-i18next="avRegistration.invalidImage"></span></div></div></div></ng-form>'), 
    $templateCache.put("avRegistration/fields/int-field-directive/int-field-directive.html", '<ng-form name="fieldForm"><div class="form-group" ng-class="{\'has-error\': fieldForm.input.$dirty && fieldForm.input.$invalid}"><label id="label-input{{index}}" for="input{{index}}"><span>{{field | customI18n : \'name\'}}</span></label><div><input type="number" class="form-control" id="input{{index}}" aria-labeledby="label-input{{index}}" name="input" min="{{field.min}}" autocomplete="off" max="{{field.max}}" ng-model="field.value" ng-model-options="{debounce: 500}" ng-disabled="field.disabled" ng-pattern="re" tabindex="0" ng-required="{{field.required}}"><p class="help-block" ng-if="!!field.help && field.help.length > 0" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><div class="input-error"><span class="error text-brand-danger" ng-show="fieldForm.input.$dirty && fieldForm.input.$invalid" ng-i18next="avRegistration.invalidDataRegEx"></span></div></div></div></ng-form>'), 
    $templateCache.put("avRegistration/fields/password-field-directive/password-field-directive.html", '<div class="form-group" ng-class="{true: \'has-error\',false: \'is-required\'}[form.passwordText.$dirty && form.passwordText.$invalid]"><label id="label-passwordText" for="passwordText"><span ng-i18next="avRegistration.passwordLabel"></span></label><div><input type="password" aria-labeledby="label-passwordText" class="form-control" ng-model="field.value" id="passwordText" autocomplete="off" ng-disabled="field.disabled" ng-i18next="[placeholder]avRegistration.passwordPlaceholder" tabindex="0" required><p class="help-block" ng-if="!field.no_help"><a href="#" ng-if="!field.help || field.help.length == 0" ng-i18next="avRegistration.forgotPassword" ng-click="forgotPassword()" tabindex="0"></a></p><p class="help-block" ng-if="!!field.help && field.help.length > 0" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><p></p><div class="input-error"><small role="alert" class="error text-danger" ng-show="form.$submitted && form.$invalid" ng-i18next="avRegistration.invalidCredentials"></small></div></div></div>'), 
    $templateCache.put("avRegistration/fields/tel-field-directive/tel-field-directive.html", '<div class="form-group"><label id="label-input{{index}}" for="input{{index}}" ng-i18next="avRegistration.telLabel"></label><div><input type="tel" class="form-control phone-login" aria-labeledby="label-input{{index}}" id="input{{index}}" ng-disabled="field.disabled" tabindex="0" name="input{{index}}" required><p class="help-block" ng-if="!field.help || field.help.length === 0" ng-i18next="avRegistration.telHelp"></p><p class="help-block" ng-if="!!(field.help || field.help_i18n) && field.help.length > 0" ng-bind-html="(field | customI18n : \'help\') | addTargetBlank"></p><p class="text-warning" ng-if="\'sms-otp\' === method" ng-i18next="avRegistration.otpHelp"></p><div class="input-error"><span class="error" ng-show="!isValidNumber" ng-i18next="avRegistration.telInvalid"></span></div></div></div>'), 
    $templateCache.put("avRegistration/fields/text-field-directive/text-field-directive.html", '<ng-form name="fieldForm"><div class="form-group" ng-class="{\'has-error\': fieldForm.input.$dirty && fieldForm.input.$invalid}"><label id="label-input{{index}}" for="input{{index}}"><span ng-if="field.name == \'username\' || field.name == \'__username\'" ng-i18next="avRegistration.usernameLabel"></span> <span ng-if="field.name != \'username\' && field.name != \'__username\'">{{field | customI18n : \'name\'}}</span></label><div><input type="text" name="input" id="input{{index}}" aria-labeledby="label-input{{index}}" class="form-control" minlength="{{field.min}}" maxlength="{{field.max}}" ng-model="field.value" ng-model-options="{debounce: 500}" ng-disabled="field.disabled" tabindex="0" ng-pattern="re" autocomplete="off" ng-required="{{field.required}}"><p class="help-block" ng-if="field.help || field.help_i18n" ng-bind-html="field | customI18n : \'help\' | addTargetBlank"></p><div class="input-error"><span class="error text-brand-danger" ng-show="fieldForm.input.$dirty && fieldForm.input.$invalid" ng-i18next="avRegistration.invalidDataRegEx"></span></div></div></div></ng-form>'), 
    $templateCache.put("avRegistration/fields/textarea-field-directive/textarea-field-directive.html", '<div class="form-group"><div class="col-sm-offset-2 col-sm-10"><textarea aria-label="{{index}}Text" id="{{index}}Text" rows="5" cols="60" tabindex="0" readonly>{{field.name}}</textarea><p class="help-block" ng-if="field.help || field.help_i18n" ng-bind-html="field | customI18n : \'help\' | addTargetBlank"></p></div></div>'), 
    $templateCache.put("avRegistration/loading.html", '<div avb-busy><p ng-i18next="avRegistration.loadingRegistration"></p></div>'), 
    $templateCache.put("avRegistration/login-controller/login-controller.html", '<div class="col-xs-12 login-controller"><div class="pad"><div av-login event-id="{{event_id}}" code="{{code}}" email="{{email}}" with-code="{{withCode}}" username="{{username}}" is-otl="{{isOtl}}" is-open-id="{{isOpenId}}" otl-secret="{{otlSecret}}" with-alt-method="{{withAltMethod}}" selected-alt-method="{{selectedAltMethod}}"></div></div></div>'), 
    $templateCache.put("avRegistration/login-directive/login-directive.html", '<section class="container-login" aria-labelledby="login-header-text"><div class="row"><div class="col-sm-12 loginheader"><h3 class="tex-center login-header-text" id="login-header-text" ng-if="!isAdmin && !isOtl && !isCensusQuery" ng-i18next="[i18next]({name: orgName})avRegistration.loginHeader"></h3><h3 class="tex-center login-header-text" id="login-header-text" ng-if="isAdmin && !isOtl" ng-i18next="[i18next]avRegistration.adminLoginHeader"></h3><h3 class="tex-center login-header-text" id="login-header-text" ng-if="!!isCensusQuery" ng-i18next="avRegistration.censusQueryHeader"></h3><h3 class="tex-center login-header-text" id="login-header-text" ng-if="isOtl" ng-i18next="avRegistration.otlHeader"></h3><div class="text-success" ng-if="!!successfulRegistration" ng-i18next="[html:i18next]avRegistration.loginAfterRegistration"></div></div>\x3c!-- Shows the alternative auth method tabs in case there\'s any --\x3e<div class="col-sm-12 alternative-auth-methods-tabs" ng-if="alternative_auth_methods"><ul class="nav nav-tabs" ng-if="method !== \'smart-link\'"><li class="default-auth-method" ng-class="{\'active\': current_alt_auth_method_id == null}"><a ng-click="setCurrentAltAuthMethod(null)"><i class="fa fa-user"></i> <span ng-i18next="avRegistration.defaultAuthMethod"></span></a></li>\x3c!-- we disable click for smart-link unless it comes from a smart-link,\n          because it doesn\'t work --\x3e<li ng-repeat="alt_auth_method in alternative_auth_methods" ng-class="{\'active\': current_alt_auth_method_id == alt_auth_method.id, \'disabled\': selectedAltMethod !== \'smart-link\' && alt_auth_method.auth_method_name === \'smart-link\'}"><a ng-click="setCurrentAltAuthMethod(alt_auth_method, true)"><i ng-if="alt_auth_method.icon" class="{{alt_auth_method.icon}}"></i> <span>{{getAltAuthMethodName(alt_auth_method)}}</span></a></li></ul></div><div class="col-sm-12" ng-if="method !== \'openid-connect\'"><form name="form" id="loginForm" role="form" class="form-horizontal"><div ng-repeat="field in login_fields" avr-field index="{{$index+1}}" ng-if="(field.steps === undefined || field.steps.indexOf(currentFormStep) !== -1) && otlStatus !== \'success\'"></div><div class="button-group"><section class="input-error" ng-if="!isCensusQuery" aria-label="{{ \'avRegistration.loginError.errorLabel\' | i18next }}"><div class="error text-danger" role="alert" ng-if="error" ng-i18next>[html:i18next]({{errorData}}){{error}}</div></section><section class="input-warn" aria-label="{{ \'avRegistration.loginError.warningLabel\' | i18next }}"><div class="warn-box" ng-if="!form.$valid || sendingData"><span class="glyphicon glyphicon-warning-sign"></span><div role="alert" ng-i18next>avRegistration.fillValidFormText</div></div></section><button type="submit" class="btn btn-block btn-lg btn-success-action" ng-if="!isCensusQuery && !isOtl && method !== \'smart-link\'" ng-i18next="avRegistration.loginButton" ng-click="loginUser(form.$valid)" tabindex="0" ng-disabled="!form.$valid || sendingData"></button> <button type="submit" class="btn btn-block btn-lg btn-success-action" ng-if="isCensusQuery" ng-i18next="avRegistration.checkCensusButton" ng-click="checkCensus(form.$valid)" tabindex="0" ng-disabled="!form.$valid || sendingData"></button> <button type="submit" class="btn btn-block btn-lg btn-success-action" ng-if="isOtl && otlStatus !== \'success\'" ng-i18next="avRegistration.otlButton" ng-click="otlAuth(form.$valid)" tabindex="0" ng-disabled="!form.$valid || sendingData"></button><div class="otl-auth" ng-if="isOtl"><div class="input-info" ng-if="otlStatus == \'querying\'"><div class="text-info" ng-i18next="avRegistration.otlStatus.querying"></div></div><div class="input-success" ng-if="otlStatus == \'success\'"><div class="success text-success" ng-i18next="[html:i18next]({code: otpCode})avRegistration.otlStatus.success"></div></div><div class="input-success" ng-if="otlStatus == \'fail\'"><div class="error text-danger" role="alert" ng-i18next="[html]avRegistration.otlStatus.fail"></div></div></div><div class="census-query" ng-if="isCensusQuery"><div class="input-info census-query" ng-if="censusQuery == \'querying\'"><div class="text-info" ng-i18next="avRegistration.censusQuerying"></div></div><div class="input-success census-query" ng-if="censusQuery == \'success\'"><div class="success text-success" ng-i18next="[html]avRegistration.censusSuccess"></div></div><div class="input-success census-query" ng-if="censusQuery == \'fail\'"><div class="error text-danger" role="alert" ng-i18next="[html]avRegistration.censusFail"></div></div></div></div></form></div><div class="col-sm-5 col-sm-offset-1 hidden-xs not-registered-yet" ng-if="registrationAllowed && !isCensusQuery && method !== \'openid-connect\' && !isOtl"><h3 class="help-h3" ng-i18next="avRegistration.notRegisteredYet"></h3><p><a ng-if="!isAdmin" href="/election/{{election.id}}/public/register" ng-i18next="avRegistration.registerHere" ng-click="goSignup()" tabindex="0"></a><br><a ng-if="isAdmin" href="{{ signupLink }}" ng-i18next="avRegistration.registerHere" tabindex="0"></a><br><span ng-i18next="avRegistration.fewMinutes"></span></p></div><div class="col-sm-12 text-center oidc-section" ng-if="method === \'openid-connect\'"><p class="oidc-login-description" ng-i18next="[html]avRegistration.openidLoginDescription"></p><span ng-repeat="provider in current_oidc_providers" class="provider-span"><button ng-click="openidConnectAuth(provider)" alt="{{provider.public_info.description}}" tabindex="0" class="btn btn-block btn-lg btn-success-action provider-btn" ng-class="{[provider.public_info.id]: true}"><img ng-if="!!provider.public_info.icon" alt="{{provider.public_info.description}}" class="logo-img" ng-src="{{provider.public_info.icon}}"> {{provider.public_info.title}}</button></span><div class="button-group"><div class="input-error"><div class="error text-danger" role="alert" ng-if="error" ng-i18next>[html:i18next]({{errorData}}){{error}}</div></div></div></div></div></section>'), 
    $templateCache.put("avRegistration/register-controller/register-controller.html", '<div class="col-xs-12 top-section"><div class="pad"><div av-register event-id="{{event_id}}" code="{{code}}" email="{{email}}"></div></div></div>'), 
    $templateCache.put("avRegistration/register-directive/register-directive.html", '<div class="container"><div class="row"><div class="col-sm-12"><h2 ng-if="!admin" class="registerheader" ng-i18next="avRegistration.registerHeader"></h2><h2 ng-if="admin" class="registerheader" ng-i18next="avRegistration.registerAdminHeader"></h2></div></div><div class="row"><div class="col-sm-6"><div ng-if="method == \'dnie\'"><a type="submit" class="btn btn-block btn-success" ng-i18next="avRegistration.registerButton" ng-href="{{ dnieurl }}/"></a></div><form ng-if="method != \'dnie\'" name="form" id="registerForm" role="form" class="form-horizontal"><div ng-repeat="field in register_fields" avr-field index="{{$index+1}}"></div><div class="col-sm-12 button-group"><div class="input-error"><div class="error text-danger" role="alert" ng-if="error" ng-bind-html="error"></div></div><div class="input-warn"><span class="text-warning" ng-if="!form.$valid || sendingData" ng-i18next>avRegistration.fillValidFormText</span></div><button type="submit" class="btn btn-block btn-success" ng-i18next="avRegistration.registerButton" ng-click="signUp(form.$valid)" tabindex="0" ng-disabled="!form.$valid || sendingData"></button></div></form></div><div class="col-sm-5 col-sm-offset-1 help-sidebar hidden-xs"><span ng-if="admin"><h3 class="help-h3" ng-i18next="avRegistration.registerAdminFormHelpTitle"></h3><p ng-i18next>avRegistration.helpAdminRegisterForm</p></span><span><p ng-if="!admin" ng-i18next>avRegistration.helpRegisterForm</p><h3 class="help-h3" ng-i18next="avRegistration.alreadyRegistered"></h3><p ng-i18next>[html]avRegistration.helpAlreadyRegisteredForm</p><a href="" ng-click="goLogin($event)" ng-i18next="avRegistration.loginHere"></a><br></span></div></div></div>'), 
    $templateCache.put("avRegistration/success.html", '<div av-success><p ng-i18next="avRegistration.successRegistration"></p></div>'), 
    $templateCache.put("avUi/change-lang-directive/change-lang-directive.html", '<a href="#" class="dropdown-toggle" data-toggle="dropdown" id="lang-dropdown-toggle" role="button" aria-expanded="false" aria-label="{{ (\'avCommon.changeLanguageMenu\' | i18next) || \'Change Language\' }}"><i class="fa fa-fw fa-lg fa-language"></i> <span class="selected-lang hidden-xs">{{ (\'avRegistration.languageName\' | i18next) || deflang }}</span> <span class="caret"></span></a><ul class="dropdown-menu" role="menu"><li ng-repeat="lang in langs"><a role="menuitem" ng-click="changeLang(lang)" ng-space-click tabindex="0">{{ (\'avRegistration.languageName\' | i18next:{lng:lang}) || lang}}</a></li></ul>'), 
    $templateCache.put("avUi/children-elections-directive/children-elections-directive.html", '<div class="row" ng-if="mode === \'toggle-and-callback\' && !hideParent"><div class="col-xs-12"><div class="btn btn-success btn-election" ng-class="{\'selected\': selectedElectionId === parentElectionId}" ng-click="click({event_id: parentElectionId})"><span ng-i18next>avAdmin.childrenElections.main</span></div></div></div><div ng-repeat="category in childrenElectionInfo.presentation.categories" ng-if="!category.hidden" class="row"><div class="col-xs-12"><h3>{{category.title}}</h3><div ng-repeat="election in category.events" class="btn btn-success btn-election" ng-disabled="election.disabled" ng-if="!election.hidden" ng-class="{\'selected\': selectedElectionId === election.event_id}" data-election-id="{{election.event_id}}" ng-click="click(election)"><i ng-if="mode === \'checkbox\'" class="fa-fw fa" ng-class="{\'fa-square-o\': !election.data, \'fa-check-square-o\': !!election.data}" aria-hidden="true"></i> {{election.title}}</div></div></div>'), 
    $templateCache.put("avUi/common-footer-directive/common-footer-directive.html", '<div class="hidden" ng-cloak av-affix-bottom ng-if="!float" class="footer-wrapper"><footer class="container footer-container row" role="navigation"><i ng-i18next="[html:i18next]({url: configService.organization.orgUrl, name: configService.organization.orgName})avCommon.poweredBy"></i></footer></div><div ng-if="!!float" class="footer-wrapper"><footer class="container footer-container row" role="navigation"><i ng-i18next="[html:i18next]({url: configService.organization.orgUrl, name: configService.organization.orgName})avCommon.poweredBy"></i></footer></div>'), 
    $templateCache.put("avUi/common-header-directive/common-header-directive.html", '\x3c!-- top navbar --\x3e<nav class="header-navbar" id="header-navbar" av-affix-top=".navbar-unfixed-top" role="navigation"><div class="header-container container"><div class="col-xs-4 header-left"><span class="logo-img-container" ng-class="{\'default-logo\': !election.logo_url}"><img alt="{{election.title}}" class="logo-img" ng-src="{{election.logo_url || defaultLogo}}"></span></div><div class="col-xs-8 header-right"><div class="hidden-xs social-container" ng-if="!!isElectionPortal && !!buttonsInfo"><span ng-repeat="q in buttonsInfo"><a href="{{ q.link }}" target="_blank" class="{{ q.class }}"><img class="social-img" ng-src="{{ q.img }}" alt="{{ q.network }}"> {{ q.button_text|truncate:25 }}</a></span></div><a ng-if="!!configService.mainVersion" target="_top" tabindex="0" class="config-version" role="button" ng-click="showVersionsModal()"><span class="hidden-xs" ng-i18next="[i18next]({version: configService.mainVersion})avCommon.showVersion"></span> <span class="visible-xs-block">{{configService.mainVersion}} </span></a><span class="dropdown" role="menuitem" av-change-lang></span> <span class="logout-container" ng-if="enableLogOut() && !isElectionPortal" ng-class="{ \'countdown\': showCountdown}"><a target="_top" tabindex="0" class="log-out-button" ng-click="confirmLogoutModal()"><div class="logout-bottom"></div><div class="logout-bar"></div><span class="glyphicon glyphicon-off"></span> <span class="logout-text hidden-xs" ng-i18next>avBooth.logout</span></a><div class="custom-tooltip"><i class="fa fa-fw fa-lg fa-caret-up"></i><div class="tooltip-inner"><b ng-i18next>avBooth.countdownTooltip.title</b><p ng-if="countdownSecs >= 60" ng-i18next="[i18next]({mins: countdownMins})avBooth.countdownTooltip.contentMins"></p><p ng-if="countdownSecs < 60" ng-i18next="[i18next]({secs: countdownSecs})avBooth.countdownTooltip.contentSecs"></p></div></div></span></div></div></nav><div id="avb-toggle" class="text-center item-block hidden"><span class="glyphicon glyphicon-play"></span></div><div class="bottom-absolute" ng-if="ballotHash"><div class="ballot-hash"><div class="hash-box"><i class="fa fa-check" aria-hidden="true"></i><div class="hash-text" ng-i18next="[i18next]({hash: ballotHash})avBooth.reviewScreen.ballotIdMessage"></div><i class="pull-right fa fa-lg fa-question-circle" ng-click="hashHelp()"></i></div></div></div>'), 
    $templateCache.put("avUi/confirm-modal-controller/confirm-modal-controller.html", '<div class="confirm-modal-controller"><div class="modal-header dialog-header-warning"><h4 class="modal-title"><span class="glyphicon glyphicon-warning-sign"></span> <span class="title" ng-bind-html="data.i18n.header"></span> <button type="button" class="close pull-right" ng-click="cancel()"><i class="fa fa-times-circle"></i></button></h4></div><div class="modal-body"><p><span class="body-data" ng-bind-html="data.i18n.body"></span></p></div><div class="modal-footer"><button class="btn btn-success" ng-click="ok()">{{ data.i18n.confirmButton }}</button> <button class="btn btn-cancel" ng-click="cancel()" ng-if="!data.hideCancelButton" ng-i18next="avCommon.cancel">avCommon.cancel</button></div></div>'), 
    $templateCache.put("avUi/documentation-directive/documentation-directive.html", '<div><h2 class="text-center text-av-secondary" ng-i18next="avDocumentation.documentation.title"></h2><p ng-i18next="avDocumentation.documentation.first_line"></p><ul class="docu-ul"><li ng-if="!!documentation.faq"><a href="{{documentation.faq}}" target="_blank" ng-i18next="avDocumentation.documentation.faq"></a></li><li ng-if="!!documentation.overview"><a href="{{documentation.overview}}" target="_blank" ng-i18next="avDocumentation.documentation.overview"></a></li><li><a href="{{auths_url}}" target="_blank" ng-i18next="avDocumentation.documentation.authorities"></a></li><li ng-if="!!documentation.technical"><a href="{{documentation.technical}}" target="_blank" ng-i18next="avDocumentation.documentation.technical"></a></li><li ng-if="!!documentation.security_contact"><a href="{{documentation.security_contact}}" target="_blank" ng-i18next="avDocumentation.documentation.security_contact"></a></li></ul><div class="documentation-html-include" av-plugin-html ng-bind-html="documentation_html_include"></div></div>'), 
    $templateCache.put("avUi/foot-directive/foot-directive.html", '<div class="commonfoot"><div class="social" style="text-align: center;"><span class="powered-by pull-left" ng-i18next="[html:i18next]({url: organization.orgUrl, name: organization.orgName})avCommon.poweredBy"></span> <a href="{{social.facebook}}" target="_blank" ng-if="!!social.facebook" aria-label="Facebook"><i class="fa fa-fw fa-lg fa-facebook"></i></a> <a href="{{social.twitter}}" target="_blank" ng-if="!!social.twitter" aria-label="Twitter"><i class="fa fa-fw fa-lg fa-twitter"></i></a> <a href="{{social.googleplus}}" target="_blank" ng-if="!!social.googleplus" aria-label="Google Plus"><i class="fa fa-fw fa-lg fa-google-plus"></i></a> <a href="{{social.youtube}}" target="_blank" ng-if="!!social.youtube" aria-label="Youtube"><i class="fa fa-fw fa-lg fa-youtube-play"></i></a> <a href="{{social.github}}" target="_blank" ng-if="!!social.github" aria-label="Github"><i class="fa fa-fw fa-lg fa-github"></i></a></div></div>'), 
    $templateCache.put("avUi/simple-error-directive/simple-error-directive.html", '<div class="av-simple-error-title" ng-transclude></div>'), 
    $templateCache.put("test/test_booth_widget.html", '<!DOCTYPE html><html><head><title>Test frame</title><meta charset="UTF-8"></head><script>function getCastHmac(auth_data, callback) {\n      callback("khmac:///sha-256;5e25a9af28a33d94b8c2c0edbc83d6d87355e45b93021c35a103821557ec7dc5/voter-1110-1dee0c135afeae29e208550e7258dab7b64fb008bc606fc326d41946ab8e773f:1415185712");\n    }<\/script><body style="overflow-y: hidden; overflow-x: hidden; padding: 0; margin: 0"><div style="width: 100%; display: block; position: absolute; top: 0; bottom: 0; scroll: none; padding: 0; margin: 0"><a class="sequent-voting-booth" href="http://sequent.dev/#/election/1110/vote" data-authorization-funcname="getCastHmac">Votar con Sequent Tech</a><script>!function(d,s,id){var js,fjs=d.getElementsByTagName(s)[0];if(!d.getElementById(id)){js=d.createElement(s);js.id=id;js.src="http://sequent.dev/avWidgets.min.js";fjs.parentNode.insertBefore(js,fjs);}}(document,"script","sequent-widgets-js");<\/script></div></body></html>'), 
    $templateCache.put("test/unit_test_e2e.html", '<div dynamic="html" id="dynamic-result"></div>');
} ]);