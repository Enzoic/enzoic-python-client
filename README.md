# Enzoic Python Client Library

TOC
-
This README covers the following topics:
* Installation
* API Overview
* The Enzoic Constructor
* Running tests

Installation
-
To Install the library using pip, run:

    $ pip install enzoic

API Overview
-
Here's the API in a nutshell.
    
    # Create a new instance of the Enzoic class - this is our primary interface for making API calls
    from enzoic import Enzoic

    enzoic = Enzoic("YOUR_API_KEY", "YOUR_API_SECRET")
    
    # Check whether a password has been compromised
    if enzoic.check_password("password_to_test"):
        print("Password is compromised")
    else:
        print("Password is not compromised")    
        
    # Check whether a specific set of credentials are compromised
    if enzoic.check_credentials("test@enzoic.com", "password_to_test"):
        print("Credentials are compromised")
    else:
        print("Credentials are not compromised")
        
    # Use the optional parameters on the check_credentials call to tweak performance 
    # by including the date/time of the last check and excluding BCrypt    
    if enzoic.check_credentials("test@enzoic.com", "password_to_test", last_check_datetime_object, [PasswordType.Bcrypt]):
        print("Credentials are compromised")
    else:
        print("Credentials are not compromised")
    
    # Get all exposures for a given user
    exposures = enzoic.get_exposures_for_user("test@enzoic.com")
    print(str(exposures["count"] + " exposures found for test@enzoic.com")
    
    # Now get the full details for the first exposure returned in the exposures response above
    details = enzoic.get_exposure_details(exposures["exposures"][0])
    print("First exposure for test@enzoic.com was " + details["title"])
    
More information in reference format can be found below.

The Enzoic Constructor
-
The standard constructor takes your API key and secret you were issued on Enzoic signup.

    enzoic = Enzoic("YOUR_API_KEY", "YOUR_API_SECRET")
    
If you were instructed to use an alternate API endpoint, you may call the overloaded constructor and pass the base URL
you were provided.

    enzoic = Enzoic("YOUR_API_KEY", "YOUR_API_SECRET", "https://api-alt.enzoic.com/v1")
    
ExposuresResponse
-
The enzoic.get_exposures_for_user method returns the response object below.

        {
            "count": <int>, # number of items in the exposures array
            "exposures": <list[str]> # A list of exposure IDs. The IDs can be used with the get_exposure_details call
            to retrieve additional information on each exposure
        }
    
ExposureDetails
-
The enzoic.get_exposure_details method returns the response object below.

        {
            "id": <str>, # The ID of the exposure.
            "title": <str>, # Title of the exposure, for breaches this is the domain of the origin site.
            "entries": <int>, # number of credentials found in the exposure.
            "date": <str>, # Date the exposure occurred as much as it is known. The value is as follows:
             # - null if the date is not known
             # - Month and day set to December 31st, if only the year is known (e.g. '2015-12-31' if Exposure date was sometime in 2015)
             # - Day set to the first of the month if only the month is known (e.g. '2015-06-01' if Exposure date was sometime in June 2015)
             # - Otherwise, exact date if exact date is known, including time
            "category": <str>, # A category for the origin website, if the exposure was a data breach.
            "passwordType": <str>, # The format of the passwords in the Exposure, e.g. 'Cleartext', 'MD5', etc.
            "exposedData": <list[str]>,  # The types of user data which were present in the Exposure e.g. [ 
                "Emails",
                "Passwords"
            ],
            "dateAdded": <str>, # The date the Exposure was found and added to the Enzoic database.
            "sourceURLs": <list[str]>, # A list of URLs the data was found at. Only present for some types of Exposures,
            like when the source was a paste site.
            "domainsAffected": <int> The number of unique email address domains in this Exposure. So, for instance, if
            the Exposure only contained 'gmail.com' and 'yahoo.com' email addresses, this number would be 2.
        }

Running Tests
-
If you wish to run tests set your PP_API_KEY and PP_API_SECRET in the pytest.ini file and then run `pytest ./tests`

License
-
This code is free to use under the terms of the MIT license.