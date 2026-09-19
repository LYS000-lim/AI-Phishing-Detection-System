import requests
from bs4 import BeautifulSoup
import pandas as pd


sources = {

    "Python Docs": {
        "url": "https://docs.python.org/sitemap.xml",
        "category": "Documentation"
    },

    "Docker Docs": {
        "url": "https://docs.docker.com/sitemap.xml",
        "category": "Documentation"
    },

    "Kubernetes Docs": {
        "url": "https://kubernetes.io/sitemap.xml",
        "category": "Documentation"
    },

    "MDN": {
        "url": "https://developer.mozilla.org/sitemap.xml",
        "category": "Documentation"
    },

}


MAX_URLS_PER_SOURCE = 200


def get_urls_from_sitemap(sitemap_url, limit=200):

    urls = []

    try:

        r = requests.get(
            sitemap_url,
            timeout=15
        )

        soup = BeautifulSoup(
            r.text,
            "xml"
        )


        # Check if this is sitemap index
        sitemap_entries = soup.find_all("sitemap")


        if sitemap_entries:

            print("  Sitemap index detected")

            sub_sitemaps = [
                x.find("loc").text
                for x in sitemap_entries
                if x.find("loc")
            ]


            for sub in sub_sitemaps:

                if len(urls) >= limit:
                    break


                try:

                    sub_r = requests.get(
                        sub,
                        timeout=15
                    )

                    sub_soup = BeautifulSoup(
                        sub_r.text,
                        "xml"
                    )


                    for item in sub_soup.find_all("loc"):

                        urls.append(item.text)

                        if len(urls) >= limit:
                            break


                except Exception as e:

                    print(
                        "  Failed sub sitemap:",
                        e
                    )


        else:

            # Normal sitemap
            for item in soup.find_all("loc")[:limit]:

                urls.append(item.text)



    except Exception as e:

        print(
            "  Sitemap error:",
            e
        )


    return urls[:limit]



results = []


for source, info in sources.items():

    print(
        "Collecting:",
        source
    )


    urls = get_urls_from_sitemap(
        info["url"],
        MAX_URLS_PER_SOURCE
    )


    print(
        "  Collected:",
        len(urls)
    )


    for url in urls:

        results.append({

            "url": url,

            "label": 1,

            "category": info["category"],

            "source": source

        })



df = pd.DataFrame(results)


# remove duplicates
df = df.drop_duplicates(
    subset=["url"]
)


df.to_csv(
    "additional_legitimate_urls.csv",
    index=False
)


print("\nDataset shape:")
print(df.shape)


print("\nSource distribution:")
print(
    df["source"].value_counts()
)