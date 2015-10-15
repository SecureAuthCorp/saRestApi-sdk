package org.secureauth.restapi.examples;


import org.secureauth.sarestapi.SAAccess;
import org.secureauth.sarestapi.data.Factors;
import org.secureauth.sarestapi.data.FactorsResponse;
import org.secureauth.sarestapi.data.IPEval;
import org.secureauth.sarestapi.data.ResponseObject;


/**
 * @author rrowcliffe@secureauth.com
 * <p>
 *     SAAccess is a class that allows access to the SecureAuth REST API. The intention is to provide an easy method to access
 *     the Secureauth Authentication Rest Services.
 * </p>
 *
 * <p>
 * Copyright 2015 SecureAuth Corporation
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
 * </p>
 */
public class GetFactorsForUser {

    //Define our User Variables
    private static String user = "lding";
    private static String password = "Password123";
    private static String otp = "";

    //Required for connectivity to Appliance
    private static String applianceHost = "qaportal2.gosecureauth.com";
    private static String appliancePort = "443";
    private static boolean applianceSSL = true;
    private static String realm = "secureauth11";
    private static String applicationID = "5e0f658a77484a0aa799bafd0f04c28c";
    private static String applicationKey = "5a264feaa95a348d8fa64bf038d8add50638bdc807f0940e817e1045c518d57d";


    public static void main(String[] args){

        //Create Instance of SAAccess Object
        SAAccess saAccess = new SAAccess(applianceHost,appliancePort,applianceSSL,realm, applicationID, applicationKey);

        System.out.println("Start Test++++++++++++++++++");
        //Grab all available Factors for a user
        FactorsResponse factorsResponse = getFactors(saAccess, user);

        System.out.println("End Test++++++++++++++++++++");

    }

    private static FactorsResponse getFactors(SAAccess saAccess,String userid){
        //Return Factors
        FactorsResponse factorsResponse = saAccess.factorsByUser(userid);
        if(!factorsResponse.getStatus().equalsIgnoreCase("invalid")){
            System.out.println("FACTORS +++++++++++++++++\n" + factorsResponse.toString());
            System.out.println("END FACTORS++++++++++++++");
            }else{
            System.out.println("Failed to get factors " + factorsResponse.getMessage());
        }
        return factorsResponse;
    }

}
