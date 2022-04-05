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

/* jshint ignore:start */
/*
 * affix-bottom-directive unit tests
 * 
 * Tests the presence of affix-bottom on different resolutions and
 * data-force-affix-width values;
 * 
 * Resolutions: 320x480, 600x800, 768x1024, 720x1280 and 1080x1920.
 * data-foce-affix-width: 568, 768 and 868.
 * 
 * affix-bottom should be present if 
 * dataForceAffixWidth > browserWidth
 */
describe("affix-bottom-directive tests", function () {

  var html;
  var dataForceAffixWidth;
  var browserWidths = [320, 600, 768, 720, 1080];
  var browserHeights = [480, 800, 1024, 1280, 1920];

  function setDataForceAffixWidth(width) {
    dataForceAffixWidth = width;
    return '<div style="background-color:yellow; height: 500px;">' +
            '<div av-affix-bottom data-force-affix-width="' +
            dataForceAffixWidth + '">' + '</div></div>';
  }

  function testResolutions() {
    for (i = 0; i < browserWidths.length; i++) {

      browser.manage().window().setSize(browserWidths[i], browserHeights[i]);
      browser.get('/#/unit-test-e2e?html=' + encodeURIComponent(html));

      if (dataForceAffixWidth > browserWidths[i]) {
        expect(element(by.css('.affix-bottom')).isPresent()).toBe(true);
      } else {
        expect(element(by.css('.affix-bottom')).isPresent()).toBe(false);
      }
    }
  }

  it("affix-bottom is present (dataForceAffixWidth: 568)", function () {
    html = setDataForceAffixWidth(568);
    testResolutions();
  });

  it("affix-bottom is present (dataForceAffixWidth: 768)", function () {
    html = setDataForceAffixWidth(768);
    testResolutions();
  });

  it("affix-bottom is present (dataForceAffixWidth: 868)", function () {
    html = setDataForceAffixWidth(868);
    testResolutions();
  });

});

/* jshint ignore:end */