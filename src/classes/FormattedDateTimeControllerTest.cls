@isTest
private class FormattedDateTimeControllerTest {
	
	@isTest static void testMethods() {
		Test.startTest();

		FormattedDateTimeController ctr = new FormattedDateTimeController();

		System.assertEquals('', ctr.getFormattedDatetime());

		DateTime evaluationDate = datetime.Now();

		ctr.valueToFormat = evaluationDate;

		string result = ctr.getFormattedDatetime();
		system.assertEquals(evaluationDate.format(), result);

		ctr.definedFormat = 'HH/mm/yyyy';

		result = ctr.getFormattedDatetime();
		system.assertEquals(evaluationDate.format('HH/mm/yyyy'), result);

		Test.stopTest();
	}
	
}