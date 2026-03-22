def classify_confidence(count):

    if count >= 3:
        return "HIGH"

    elif count == 2:
        return "MEDIUM"

    else:
        return "LOW"


print("\nRISK OUTPUT:\n")

for ioc, count in ioc_count.items():

    level = classify_confidence(count)

    print(f"{ioc} -->> Score: {count} -->> Level: {level}")
