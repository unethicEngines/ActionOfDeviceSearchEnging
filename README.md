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

## Revision of Table 11: The Multi-port identified protocols and their corresponding number of probe types and the list of ports. 
| Service                                  | NumberofTypes | TargetPorts                                                  |
| ---------------------------------------- | ------------- | ------------------------------------------------------------ |
| Secure Shell                             | 2             | [22, 2222]                                                   |
| Network Basic Input/Output System        | 7             | [25, 137, 139, 7587, 11382, 23915, 29844, 31530, 34125, 34303, 40013, 44893, 47415] |
| OpenVPN                                  | 2             | [443, 500, 1194]                                             |
| Socket Secure                            | 4             | [1080, 5555, 5678, 7777, 7788, 7890, 8888]                   |
| Microsoft SQL Server                     | 5             | [427, 1433, 1434, 7025, 10001, 16592, 20748, 21429, 22637, 28864, 31980, 41372, 51668, 55010, 61870] |
| Mikrotik Router                          | 7             | [111, 2000, 4478, 7215, 8728, 10151, 23810, 24285, 27527, 32400, 38676, 40454, 41787, 49122] |
| Session Initiation Protocol              | 6             | [4871, 5060, 5061, 6060, 6788, 8320, 10325, 10326, 14396, 16319, 19867, 25841, 27650, 31492, 34182, 35042, 37997, 39510, 39849, 46321, 46837, 49699, 50929, 54023, 58038] |
| NAT Port Mapping Protocol                | 6             | [69, 80, 520, 1812, 1877, 2869, 3389, 3600, 3786, 5351, 5432, 6340, 6604, 6969, 7001, 7320, 7398, 8000, 8290, 8835, 8945, 9999, 10690, 11211, 12205, 16397, 17180, 23205, 23209, 23627, 24046, 24588, 24921, 28348, 30718, 32626, 34425, 34664, 35494, 37834, 40257, 40891, 41145, 41216, 41407, 45127, 45567, 46062, 47868, 51168, 51261, 53413, 53878, 54232, 57385, 58682, 59478, 64738, 64940, 65501] |
| X Window System                          | 4             | [6000, 6001, 6002]                                           |
| Redis                                    | 5             | [6379, 6666, 7000]                                           |
| Ubiquiti Discovery Protocol              | 4             | [19, 382, 3745, 4095, 5094, 9185, 10001, 11977, 18798, 19132, 20004, 22153, 22834, 24669, 27464, 32157, 32521, 32889, 34344, 36712, 38130, 39396, 39509, 42481, 44045, 47395, 51887] |
| Domain Name System                       | 7             | [53, 69, 174, 1967, 2967, 5353, 9646, 10001, 20104, 21301, 28159, 29997, 30855, 32276, 37165, 47268, 48409] |
| Network Time Protocol                    | 8             | [123, 1632, 2112, 9577, 14983, 23708, 33270, 36503, 42507, 51759, 52315, 53075, 61172, 65037] |
| X Display Manager Control Protocol       | 2             | [69, 177, 1910, 12816, 13495, 13636, 14694, 15330, 15742, 17790, 25622, 30397, 32888, 36997, 38792, 40538, 45197, 47122, 50647, 59675] |
| Negotiation of NAT-Traversal in the IKE  | 1             | [500, 1194, 1891, 3997, 4304, 4500, 6154, 7928, 8209, 12390, 12429, 14973, 16160, 20969, 22993, 24512, 25270, 26680, 28200, 31788, 33172, 34949, 34956, 38381, 38538, 40126, 40224, 40727, 42850, 42910, 44568, 44806, 45708, 46061, 49109, 49147, 51822, 54015, 59491, 63038, 63284, 64367] |
| Routing Information Protocol             | 6             | [520, 2222, 4301, 17948, 23103, 27305, 35315, 35405, 36333, 38527, 64648] |
| Universal Plug and Play                  | 3             | [1474, 1900, 16435, 21721, 24695, 32410, 32414, 37215, 38412, 38599, 45913, 56721] |
| Citrix MetaFrame application             | 2             | [1604, 23168, 23261, 33352, 38205, 38890, 41912, 46508, 58206, 58344, 58686] |
| RADIUS                                   | 2             | [1645, 1812, 6574, 16531, 20899, 26701, 29322, 48794, 52452, 54347] |
| Simple Object Access Protocol            | 3             | [370, 2191, 3702, 8446, 21229, 35830, 56006]                 |
| Apple Remote Desktop                     | 4             | [3283, 9334, 13853, 14434, 17847, 43041, 47851, 52327, 55123, 56498, 62279, 63176] |
| A2S Query protocol                       | 3             | [4131, 8626, 12893, 18745, 21025, 22767, 24018, 27015, 27016, 27105, 28015, 32165, 41700, 57896] |
| VxWorks Wind DeBug agents                | 3             | [4210, 12819, 14567, 14771, 17185, 18265, 20379, 26764, 28940, 31339, 48717, 49530, 49661, 51202, 57125, 57175, 57381, 57609, 62151, 63735] |
| Datagram Transport Layer Security        | 2             | [5061, 5257, 5684, 5738, 6625, 7243, 11920, 19604, 20374, 20720, 21406, 28845, 31436, 31966, 33703, 38765, 39434, 39783, 50338, 52540, 52668, 52685, 53405, 59168, 63340] |
| DNS-Based Service Discovery              | 2             | [5353, 18235, 18529, 24173, 24626, 25301, 26081, 29939, 45293, 62663, 65337] |
| Building Automation and Control Networks | 2             | [5407, 6833, 7642, 9140, 18427, 25337, 31513, 33728, 42168, 47808] |
| PC Anywhere                              | 4             | [5001, 5632, 10522, 31348, 39939, 41650, 42730, 50388, 57664] |
| Distributed hash table                   | 3             | [6881, 13001, 24530, 29579, 29899, 44629, 44633, 47199, 48097, 48688] |
| Simple Mail Transfer Protocol            | 2             | [25, 587]                                                    |
| GPRS Tunneling Protocol                  | 2             | [2123, 2152, 3386]                                           |
| Session Traversal Utilities for NAT      | 3             | [3478, 8088, 37833]                                          |
| Constrained Application Protocol         | 2             | [5673, 5683]                                                 |
| Android Debug Bridge                     | 2             | [5555, 9001]                                                 |
| Java Remote Method Invocation            | 1             | [6000, 10001]                                                |
| Java Debug Wire Protocol                 | 1             | [8000, 9000]                                                 |
| All-Seeing Eye                           | 1             | [8000, 11211]                                                |

