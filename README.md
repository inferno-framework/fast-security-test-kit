# Inferno FAST Security IG Test Kit 

This is a work-in-progress collection of tests for the [FAST Security
IG](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/index.html) using the
[Inferno Framework](https://inferno-framework.github.io/inferno-core/).

Please note that this test kit currently is of very limited scope and currently
only contains tests for the
[Discovery](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/discovery.html)
section of the specification.  These tests were initially developed in support
of the September 2021 HL7® FHIR® Connectathon.

Future development may increase test coverage of this IG.

## Instructions

- Clone this repo.
- Run `setup.sh` in this repo.
- Run `run.sh` in this repo.
- Navigate to `http://localhost`. The SMART test suite will be available.

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at
```
http://www.apache.org/licenses/LICENSE-2.0
```
Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
