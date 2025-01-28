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
    function(
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
    }
  );
