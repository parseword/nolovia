<?php
/*
 * Copyright 2015-2017 Shaun Cummiskey, <shaun@shaunc.com> <http://shaunc.com>
 * <https://github.com/ampersign/nolovia>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
 
/* POPO to hold server list configuration properties */
class ServerList {

    private $name = null;
    private $filePath = null;
    private $uri = null;
    private $listStartDelimiter = '';
    private $listEndDelimiter = '';
    private $minimumExpectedBytes = 0;
    private $validationText = '';
    private $replacePatterns = array();
    private $matchAllPattern = '';

    public function __construct($name) {
        $this->name = $name;
    }

    public function getName() {
        return $this->name;
    }
    function setName($name) {
        $this->name = $name;
    }
    public function getFilePath() {
        return $this->filePath;
    }
    function setFilePath($filePath) {
        $this->filePath = $filePath;
    }
    public function getUri() {
        return $this->uri;
    }
    function setUri($uri) {
        $this->uri = $uri;
    }
    public function getData() {
        return $this->data;
    }
    function setData($data) {
        $this->data = $data;
    }
    public function getListStartDelimiter() {
        return $this->listStartDelimiter;
    }
    function setListStartDelimiter($listStartDelimiter) {
        $this->listStartDelimiter = $listStartDelimiter;
    }
    public function getListEndDelimiter() {
        return $this->listEndDelimiter;
    }
    function setListEndDelimiter($listEndDelimiter) {
        $this->listEndDelimiter = $listEndDelimiter;
    }
    public function getMinimumExpectedBytes() {
        return $this->minimumExpectedBytes;
    }
    function setMinimumExpectedBytes($minimumExpectedBytes) {
        $this->minimumExpectedBytes = $minimumExpectedBytes;
    }
    public function getValidationText() {
        return $this->validationText;
    }
    function setValidationText($validationText) {
        $this->validationText = $validationText;
    }
    public function getReplacePatterns() {
        return $this->replacePatterns;
    }
    function setReplacePatterns($replacePatterns) {
        if (!is_array($replacePatterns)) {
            throw new Exception('Argument to ServerList::setReplacePatterns() must be an array');
        }
        $this->replacePatterns = $replacePatterns;
    }
    public function getMatchAllPattern() {
        return $this->matchAllPattern;
    }
    function setMatchAllPattern($matchAllPattern) {
        $this->matchAllPattern = $matchAllPattern;
    }
}
