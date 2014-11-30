VirusTotal-Private-API-Script
=============================

A VT script to pull large amounts of data from hashes and store them, then present them. 

If you can think of anything to improve this, let me know!


Requirements:

  This script is meant to be run on Python2.7 and run with a sqlite3 database named hashes.db.
  You will need to modify the table names inside the script at this time. Where you say SalityTCP, SalityUDP and SalityURL 
  will have to be changed to match what you want. If you just want to overwrite your previous material, leave it be.
  

A sample usage of this script would be

./VTScraper -t Sality -e 'engines:"Sality" behavior:"HTTP"' -a 10

This will create a table named SalityUDP, SalityTCP,  SalityURL and insert the results from search. It will pull an additional
3,000 hashes as the '-a 10' was used. 300 hashes can take between 4-5 minutes to process and request on a low end PC. 
Judge accordingly with how many hashes you want.

