Purpose:
-   This is a multi-user blog.  Users can create unique logins to post/edit their own blogs, comment or like other blogs.

How:
-   Runs on Google App Engine. 
-   https://blog-151016.appspot.com/blog
-   To run locally, install Google Cloud SDK (https://cloud.google.com/sdk/downloads), then run "dev_appserver.py ." in this folder (be sure the PATH for this script is set in your environment variable).  The home page will be at "localhost:8080/blog".

Author:
-   Brad Droegkamp

References:
-   Udacity Intro to Backend course provided all structure and criteria requirements

Todo:
-   Replace links with buttons (per Udacity reviewer: https://v4-alpha.getbootstrap.com/components/buttons/#button-tags)
-   CSS improvements, including replacing raw text links with svg fonts (per Udacity reviewer:  http://getbootstrap.com/components/)
-   Add "more comments" button to show more than 3 comments per post
-   Per Udacity instructor, modularize the code.  It isn't ideal (or practical for future use) the entire framework is encompassed in one blog.py file
-   Use docstrings on rest of code.  Per instructor's suggestion, I started this with the Blog class