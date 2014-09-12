/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2010 - Salesforce.com
 * 
 * The Apex ESAPI implementation is published by Salesforce.com under the New BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Yoel Gluck (securecloud .at. salesforce.com) <a href="http://www.salesforce.com">Salesforce.com</a>
 * @created 2010
 */

/**
 * This class contains unit tests for validating the behavior of Apex classes
 * and triggers.
 *
 * Unit tests are class methods that verify whether a particular piece
 * of code is working properly. Unit test methods take no arguments,
 * commit no data to the database, and are flagged with the testMethod
 * keyword in the method definition.
 *
 * All test methods in an organization are executed whenever Apex code is deployed
 * to a production organization to confirm correctness, ensure code
 * coverage, and prevent regressions. All Apex classes are
 * required to have at least 75% code coverage in order to be deployed
 * to a production organization. In addition, all triggers must have some code coverage.
 * 
 * The @isTest class annotation indicates this class only contains test
 * methods. Classes defined with the @isTest annotation do not count against
 * the organization size limit for all Apex scripts.
 *
 * See the Apex Language Reference for more information about Testing and Code Coverage.
 */
@isTest
private class SFDCAccessControllerTest { 

    static testMethod void testAccessControl() {
        Contact c = new Contact();
        
        
        List<Schema.SObjectField> contactLastModifiedDate = new List<Schema.SobjectField>{
            Schema.Contact.fields.LastModifiedDate
        };
        
        // cannot change lastmodified date
        System.assertEquals(false, Util.AccessController.isAuthorizedToUpdate(Schema.Contact.SobjectType, contactLastModifiedDate));
        System.assertEquals(false, Util.AccessController.isAuthorizedToUpdate(Schema.Contact.SobjectType, new List<String>{'LastModifiedDate'}));
        System.assertEquals(false, Util.AccessController.isAuthorizedToCreate(Schema.Contact.SobjectType, contactLastModifiedDate));
        System.assertEquals(false, Util.AccessController.isAuthorizedToCreate(Schema.Contact.SobjectType, new List<String>{'LastModifiedDate'}));

        try{
            Util.AccessController.assertAuthorizedToUpdate(Schema.Contact.SobjectType, contactLastModifiedDate);
            System.assert(false, 'Should not succeed in saving as Lastmodified date is not updateable');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.NO_UPDATE, ex.getExceptionReason());
            System.assertEquals('Contact', ex.getExceptionObject());
            System.assertEquals('LastModifiedDate', ex.getExceptionField());
        }
        
        try{
            Util.AccessController.assertAuthorizedToCreate(Schema.Contact.SobjectType, contactLastModifiedDate);
            System.assert(false, 'Should not succeed in saving as Lastmodified date is not creatable');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.NO_CREATE, ex.getExceptionReason());
            System.assertEquals('Contact', ex.getExceptionObject());
            System.assertEquals('LastModifiedDate', ex.getExceptionField());
        }
        
        
        try{
            Util.AccessController.assertAuthorizedToUpdate(Schema.Contact.SobjectType, new List<String>{'LastModifiedDate'});
            System.assert(false, 'Should not succeed in saving as Lastmodified date is not updateable');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.NO_UPDATE, ex.getExceptionReason());
            System.assertEquals('Contact', ex.getExceptionObject());
            System.assertEquals('LastModifiedDate', ex.getExceptionField());
        }
        
        try{
            Util.AccessController.assertAuthorizedToCreate(Schema.Contact.SobjectType, new List<String>{'LastModifiedDate'});
            System.assert(false, 'Should not succeed in saving as Lastmodified date is not creatable');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.NO_CREATE, ex.getExceptionReason());
            System.assertEquals('Contact', ex.getExceptionObject());
            System.assertEquals('LastModifiedDate', ex.getExceptionField());
        }
        
        
        try{
            Util.AccessController.assertAuthorizedToCreate(Schema.ApexLog.SobjectType, 
                                new List<Schema.SObjectField>{Schema.ApexLog.fields.Status});
            System.assert(false, 'Should not succeed in saving as ApexLog  is not creatable');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.NO_CREATE, ex.getExceptionReason());
            System.assertEquals('ApexLog', ex.getExceptionObject());
            System.assertEquals(null, ex.getExceptionField());
        }
        
        try{
            Util.AccessController.assertAuthorizedToUpdate(Schema.ApexLog.SobjectType, 
                                new List<Schema.SObjectField>{Schema.ApexLog.fields.Status});
            System.assert(false, 'Should not succeed in saving as ApexLog  is not updateable');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.NO_UPDATE, ex.getExceptionReason());
            System.assertEquals('ApexLog', ex.getExceptionObject());
            System.assertEquals(null, ex.getExceptionField());
        }
        
        try{
            Util.AccessController.assertAuthorizedToCreate(Schema.ApexLog.SobjectType, 
                                new List<String>{'Status'});
            System.assert(false, 'Should not succeed in saving as ApexLog  is not creatable');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.NO_CREATE, ex.getExceptionReason());
            System.assertEquals('ApexLog', ex.getExceptionObject());
            System.assertEquals(null, ex.getExceptionField());
        }
        
        try{
            Util.AccessController.assertAuthorizedToUpdate(Schema.ApexLog.SobjectType, 
                                new List<String>{'Status'});
            System.assert(false, 'Should not succeed in saving as ApexLog  is not updateable');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.NO_UPDATE, ex.getExceptionReason());
            System.assertEquals('ApexLog', ex.getExceptionObject());
            System.assertEquals(null, ex.getExceptionField());
        }
        
        System.assertEquals(false,Util.AccessController.isAuthorizedToCreate(Schema.ApexLog.SobjectType, 
                                new List<Schema.SObjectField>{Schema.ApexLog.fields.Status}));
                                
        System.assertEquals(false, Util.AccessController.isAuthorizedToCreate(Schema.ApexLog.SobjectType, 
                                new List<String>{'Status'}));
        
        System.assertEquals(false,Util.AccessController.isAuthorizedToUpdate(Schema.ApexLog.SobjectType, 
                                new List<Schema.SObjectField>{Schema.ApexLog.fields.Status}));
                                
        System.assertEquals(false, Util.AccessController.isAuthorizedToUpdate(Schema.ApexLog.SobjectType, 
                                new List<String>{'Status'}));
        
        
        System.assertEquals(Contact.SobjectType.getDescribe().isDeletable(), 
                    Util.AccessController.isAuthorizedToDelete(Schema.Contact.SobjectType));
        
        List<Schema.SobjectField> createableFields = Util.AccessController.getCreatableFields(c);
        List<Schema.SobjectField> updateableFields = Util.AccessController.getUpdateableFields(c);
        List<Schema.SobjectField> viewableFields = Util.AccessController.getViewableFields(c);
        
        System.assertEquals(createableFields, Util.AccessController.getCreatableFields(Contact.getSObjectType()));
        System.assertEquals(updateableFields, Util.AccessController.getUpdateableFields(Contact.getSObjectType()));
        System.assertEquals(viewableFields,Util.AccessController.getViewableFields(Contact.getSObjectType()));
        
        // will throw exception if in bad state
        Util.AccessController.assertAuthorizedToView(Schema.Contact.SobjectType, viewableFields);
        Util.AccessController.assertAuthorizedToCreate(Schema.Contact.SobjectType, createableFields);
        Util.AccessController.assertAuthorizedToUpdate(Schema.Contact.SobjectType, updateableFields);
        
        System.assert(Util.AccessController.isAuthorizedToView(Schema.Contact.SobjectType, viewableFields), 'should be able to view');
        System.assert(Util.AccessController.isAuthorizedToCreate(Schema.Contact.SobjectType, createableFields), 'should be able to view');
        System.assert(Util.AccessController.isAuthorizedToUpdate(Schema.Contact.SobjectType, updateableFields), 'should be able to update');
        
        System.assert(Util.AccessController.isAuthorizedToView(Schema.Contact.SobjectType, new List<String>{'LastName'}), 'should be able to view');
        System.assert(Util.AccessController.isAuthorizedToCreate(Schema.Contact.SobjectType, new List<String>{'LastName'}), 'should be able to create');
        System.assert(Util.AccessController.isAuthorizedToUpdate(Schema.Contact.SobjectType, new List<String>{'LastName'}), 'should be able to update');
        
        String badFieldName = 'SomeCrazyBadFieldName';
        try {
            System.assert(Util.AccessController.isAuthorizedToView(Schema.Contact.SobjectType, 
                                new List<String>{'LastName', badFieldName}), 'should be able to view');
            System.assert(false, 'Should not come here');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.FIELD_NOT_FOUND, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.GENERIC, ex.getExceptionReason());
            System.assertEquals('Contact', ex.getExceptionObject());
            System.assertEquals(badFieldName, ex.getExceptionField());
        }

        try {
            System.assert(Util.AccessController.isAuthorizedToCreate(Schema.Contact.SobjectType, 
                                new List<String>{'LastName', badFieldName}), 'should be able to view');
            System.assert(false, 'Should not come here');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.FIELD_NOT_FOUND, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.GENERIC, ex.getExceptionReason());
            System.assertEquals('Contact', ex.getExceptionObject());
            System.assertEquals(badFieldName, ex.getExceptionField());
        }
        
        try {
            System.assert(Util.AccessController.isAuthorizedToUpdate(Schema.Contact.SobjectType, 
                                new List<String>{'LastName', badFieldName}), 'should be able to view');
            System.assert(false, 'Should not come here');
        } catch(SFDCAccessControlException ex) {
            System.assert(!String.isBlank(ex.getText()));
            System.assertEquals(SFDCAccessControlException.ExceptionType.FIELD_NOT_FOUND, ex.getExceptionType());
            System.assertEquals(SFDCAccessControlException.ExceptionReason.GENERIC, ex.getExceptionReason());
            System.assertEquals('Contact', ex.getExceptionObject());
            System.assertEquals(badFieldName, ex.getExceptionField());
        }
        
    }
    
}