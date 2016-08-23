
function validatePassword(arg_pw) {
	var minLength = 6; // Minimum password length
	var maxLength = 16; // Maximum password length
	// check for minimum length
	if (arg_pw.length < minLength) {
		alert('Your password must be at least ' + minLength + ' characters long. Try again.');
		document.submit_form.password1.focus();
		return false;
	}
	// check for maximum length
	if (arg_pw.length > maxLength) {
		alert('Your password must be no more than ' + maxLength + ' characters long. Try again.');
		document.submit_form.password1.focus();
		return false;
	}
	// check for embedded spaces
	if (arg_pw.indexOf(" ") > -1) {
		alert("No spaces are permitted.");
		document.submit_form.password1.focus();
		return false;
	}
	return true
}

function validateTwoPasswords() {
	var pw1 = document.submit_form.password1.value; // 1st password entry
	var pw2 = document.submit_form.password2.value; // 2nd password entry
	// check for a value in both fields.
	if (pw1 == '' || pw2 == '') {
		alert('Please enter your password twice.');
		document.submit_form.password1.focus();
		return false;
	}
	if (pw1 != pw2) {
		alert ("You did not enter the same password twice. Please re-enter.");
		document.submit_form.password1.focus();
		return false;
	}
	// SUCCESS
	return validatePassword(pw1);
}
