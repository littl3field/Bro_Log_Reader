from bat import bro_log_reader
from bat.utils import vt_query


    # Create a VirusTotal Query Class
    vtq = vt_query.VTQuery()

    risky_tlds = set(['info', 'tk', 'xyz', 'online', 'club', 'ru', 'website', 'in', 'ws', 'top', 'site', 'work', 'biz', 'name', 'tech'])

    # Run the bro reader on the dns.log file looking for risky TLDs
    reader = bro_log_reader.BroLogReader(args.bro_log, tail=True)
    for row in reader.readrows():

        # Pull out the TLD
        query = row['query']
        tld = tldextract.extract(query).suffix

        # Check if the TLD is in the risky group
        if tld in risky_tlds:
            # Make the query with the full query
            results = vtq.query_url(query)
            if results.get('positives'):
                print('\nTest')
                print(results)
