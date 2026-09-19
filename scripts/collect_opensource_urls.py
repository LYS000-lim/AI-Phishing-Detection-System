import requests
from bs4 import BeautifulSoup
import pandas as pd


sources = {

    "GitHub Flask": {
        "url": "https://github.com/pallets/flask",
        "category": "Open Source"
    },

    "GitHub TensorFlow": {
        "url": "https://github.com/tensorflow/tensorflow",
        "category": "Open Source"
    },

    "GitHub Scikit Learn": {
        "url": "https://github.com/scikit-learn/scikit-learn",
        "category": "Open Source"
    },

    "GitLab": {
        "url": "https://gitlab.com/gitlab-org/gitlab",
        "category": "Open Source"
    },

}


MAX_URLS_PER_SOURCE = 100


results = []


for source, info in sources.items():

    print("Collecting:", source)

    try:

        r = requests.get(
            info["url"],
            timeout=15
        )


        soup = BeautifulSoup(
            r.text,
            "html.parser"
        )


        links = set()


        for a in soup.find_all("a", href=True):

            href = a["href"]


            if href.startswith("http"):

                links.add(href)



        count = 0


        for url in links:

            results.append({

                "url": url,

                "label": 1,

                "category": info["category"],

                "source": source

            })


            count += 1


            if count >= MAX_URLS_PER_SOURCE:

                break



    except Exception as e:

        print(source, e)



df = pd.DataFrame(results)


df = df.drop_duplicates(
    subset=["url"]
)


df.to_csv(
    "additional_opensource_urls.csv",
    index=False
)


print("\nDataset shape:")
print(df.shape)


print("\nSource distribution:")
print(
    df["source"].value_counts()
)