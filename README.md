# aci-python

To run:  
  python 3 script_name.py
  or
  python3 script_name.py --fabric lab --user admin --pass 'cisco!23' --chg CHG12345

For help:  
  python3 script_name.py -h

To check and install packages:  
  python3 -m pip list  
  python3 -m pip install -r requirements.txt

Scripts generate and store logs in the logs folder after they are ran (logs auto rotate between 2 files).


Scripts:

-get_token.py
  
  Scripts will use this function to login and retrieve a token.  
  Update lines 42-63 for your fabric name/URL.
  
-snapshot.py

  Scripts will use this to create a pre and post snapshot with changed number
  
