public class FormattedDateTimeController {
	public DateTime valueToFormat { get; set; } //property that reads the datetime value from component attribute tag
	public String definedFormat { get; set;} //property that reads the string value from component attribute tag

	public String getFormattedDatetime() {
		if (valueToFormat == null) {
				return ''; 
		} else { 
			if (definedFormat == null) {
				return valueToFormat.format(); //return the full date/time in user's locale and time zone
			} else { 
				return valueToFormat.format(definedFormat);  //Specify Time zone like IST,CST
			}
		}
	}
}