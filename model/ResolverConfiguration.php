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
 
/* POPO to hold resolver configuration properties */
class ResolverConfiguration {
    
    private $name = null;
    private $enabled = false;
    private $filePath = null;
    private $zoneDefinitionTemplate = null;
    
    public function __construct($name) {
        $this->name = $name;
    }

    public function getName() {
        return $this->name;
    }
    function setName($name) {
        $this->name = $name;
    }
    public function getEnabled() {
        return $this->enabled;
    }
    public function isEnabled() {
        return $this->enabled;
    }
    function setEnabled($enabled) {
        $this->enabled = $enabled;
    }
    public function getFilePath() {
        return $this->filePath;
    }
    function setFilePath($filePath) {
        $this->filePath = $filePath;
    }
    public function getZoneDefinitionTemplate() {
        return $this->zoneDefinitionTemplate;
    }
    function setZoneDefinitionTemplate($zoneDefinitionTemplate) {
        $this->zoneDefinitionTemplate = $zoneDefinitionTemplate;
    }
}
