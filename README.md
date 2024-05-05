# ActionOfDeviceSearchEnging
The repository for "Device Search Engines: A Double-Edged Sword in Network Security and Privacy".


## Structure

### Datasets

- We purposed a semi-automated framework for discovering services that can reflect ScanIPs of device search engines. The full list of 106,132 Mirror Services we collected is in `Datasets/Mirror_Services.json`.
- The pattern format for a mirror service is denoted as [server_ip, server_port, matchPattern, form].


### Tools

- In Appendix "METHODOLOGY",  we implemented a semi-automatic framework for discovering ScanIPs of device search engines based on Mirror services. 
- This framework consists of three components: 1) Mirror Service finder for matching records by Mirror Service type patterns; 2) ScanIP collector for collecting ScanIPs from Mirror Service records; 3) Mirror type expansion module for distill new types of mirror service from ScanIP records. 
- The source code for this tool is present in `Tools/ScanIP_collection`.


