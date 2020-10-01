SAAccess
===========

SAAccess is a solution that allows access to SecureAuth's REST api. The intention
is to provide a easy and a standard method to to access the SecureAuth Appliance REST
service. Developers working with the REST API tend to write their own REST
client using either Jersey libraries or base java IO classes. SAAccess sdk
relies on a core class org.secureauth.sarestapi.SAAccess.

The SDK version 1.0.1. is written to support SecureAuth Appliance 9.0.2 and newer.
 
The SDK will support SecureAuth 8.2 but some capabilities were not available in SecureAuth 8.2

This is a community driven project, if you would like to contribute please fork and update. Changes will be reviewed then added to the project.

Requirements:
------------
* Requires Java 11
* Requires gradle to build the package

Dependencies:
------------
* jackson-jaxrs-json-provider 2.7.3
* jersey-client 2.5.1
* Commons Codec 1.10
* SLF4J 1.7.28
* jaxb 2.3.0
* junit 5.1.0

Building:
--------
1. Fork the Repo to local machine
2. Run gradle build

Copy the libs folder in $PROJECTHOME/build to your classpath for use with any of your projects
Or add saRestApi-sdk as a dependency in your current project.

Usage:
-----

In order to use the SecureAuth Rest API you need to generate your Application ID and Application key from the Administration Console.
Each Realm has a unique ApplicationID and ApplicationKey. You can generate your realm's ID and Keys by selecting the realm you want to enable.
Then select Registration Methods and Scroll Down to Authentication API. Click the Generate App/Key button.

```java

String applianceHost = "example.domain.com";
String appliancePort = "443";
boolean applianceSSL = true;
boolean selfSigned = true;
String realm = "secureauth2";
String applicationID = ".........";
String applicationKey = ".........";

 /*
 This will create the instance of the SAAccess which is able to execute REST calls.
 */
ISAAccess saAccess = SAFactory.of(applianceHost, appliancePort, applianceSSL, selfSigned, realm, applicationID, applicationKey);

try {
  // To validate a user exists in your data store all you need to run the following.
  System.out.println(saAccess.validateUser("USERNAME").toString());

  ResponseObject validUser = saAccess.validateUser("USERNAME")
  if(validUser != null){
     if(validUser.getStatus().equalsIgnoreCase("found")){
         System.out.println("Matched User")
     }
  if(validUser.getStatus().equalsIgnoreCase("not_found")){
      System.out.println("User was not found in DataStore!")
  }
}catch (SARestAPIException e){
    //handle exception
}

```

Changes:
--------
With the 9.0Support Branch the following was changed

* Updated Data Objects to extend from a BaseResponse Object
* Created Interfaces for making the implementation of the API easier.
* Refactored the structure of the data objects
* Updated Data Objects toString to support JSON Output.
* Created a Client Side Filter to force specific headers existing on each request
* Updated Query Objects to support new BehaveBio and IDM Features
* Updated TestClass to use Interfaces
* Created Individual Interface Impl classes



For Enhancements or updates please use the github issues.
 
