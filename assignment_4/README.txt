This assignment was to perform a basic form of SQL injection attack
on a mock server, whose code was also given to us as part of the assignment.

The server at first prompts the user for a password, then once logged in
allows him to search for some items in the database. There is also an
admin login page.

The goal was to bypass the first login prompt (without knowing the password),
then exploit the search functionality to find the admin password, which
could be used to log in as an administrator and reveal the flag.





EXPLOIT PROCESS:
The exploit works as follows:
    When prompted for a password, input the following:
        ' OR 1=1 --
    We are now successfully logged in and can search the database. Search for:
        ' and 1 = 2 UNION SELECT id, username, password from users WHERE username = 'admin' --
    This returns the DB record associated with the admin account, from which
    we can see that the admin password is "sup3r4dm1nP@5sw0rd".
    We can now browse to the admin loging page (.../admin), input the above
    password and retrieve the flag:
        TUC{SQLi_1s_4w3s0m3_NGL_4nd_th3_sky_1s_blu3}





EXPLANATION:
An explanation of the queries used at each step can be found below:

    - for bypassing the login page:
        ' OR 1=1 --

        The query that's actually executed when this is given as a password
        (as one can see from the code, see app.py, line 40) is:
            SELECT * FROM users WHERE username = 'user' AND password = '' OR 1=1 --'
        
        > we use the first single quotation mark (') to exit the one that is
          open for the password to be placed inside
        > we then OR with a condition that always evaluates to true (1=1), in order
          for the query to return some data and not NULL, which is what the code
          checks for in order to log us in (see app.py, line 46)
        > we then use the comment characters (--) to avoid whatever follows our
          always true statement and make sure that thats where the query ends
          (in this specific case, if we ommited the comment characters an error
          would be caused because of the trailing quotation mark)
    
    - for retrieving the admin password:
        ' and 1 = 2 UNION SELECT id, username, password from users WHERE username = 'admin' --

        The query that's actually executed when this is given as an item to search
        for (see app.py, line 82) is:
            SELECT name,category,price FROM items WHERE name = '' and 1 = 2 UNION SELECT id, username, password from users WHERE username = 'admin' --'

        > we use the first single quotation mark to exit the open one, just like
          above
        > we then AND with a condition that always evaluates to false, in order to
          discard any potential results from the 'items' table
        > we then UNION with the actual query we are interested in, which is
          SELECT id, username, password from users WHERE username = 'admin'
          Note that the resulting tuple has 3 columns, just like the original query
          would if it had any results, which is required for UNION to work as
          intended. Also note that in this specific case, because of the way the
          code works (see app.py, line 89), if no WHERE clause was specified the
          result would be the same, as the first resulting tuple would be the one
          with id=1, which is the admin account. We could also alter the WHERE
          clause to get the user account's password (!@$%!%randomstringd03sntm4tt3r).
        > we then comment out the rest of the query, just like above.





NOTES:
    - The attack could also be done in other ways, perhaps more straightforward, if
      the app didn't check for ';' in the inputs.
