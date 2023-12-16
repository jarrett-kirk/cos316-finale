# cos316-finale

To run our code, all that needs to be done is to cd into our cos316-finale/client folder. Once that is done, execute the following code:

go run main.go

You can use our firewall project by making direct edits to the main.go file. Specifically, you can change the input .csv file(we provide three options, mirai-attack, syn-Dos-attack, and testing-local). Furthermore, you can change the chains and rules by using the functions addUserChain, addRule(), DeleteRule(). When creating the table, the default policy is passed, which can be changed to be ACCEPT or DROP. Finally, the filterData() function is used to print any IP packets that have been accepted.
 