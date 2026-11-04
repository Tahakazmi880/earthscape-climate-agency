# Prepares the web app's data files from the cleaned project dataset.
# Run once: python3 prep_data.py
import pandas as pd
import numpy as np
import json, os

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
os.makedirs(DATA, exist_ok=True)
SRC = "/home/hatch/workspace/eproject"

df = pd.read_csv(f"{SRC}/data/cleaned/GlobalLandTemperaturesByCountry_cleaned.csv")
df['dt'] = pd.to_datetime(df['dt'])
df['year'] = df['dt'].dt.year
df['month'] = df['dt'].dt.month

# Yearly averages per country (explorer page)
yearly = df.groupby(['Country', 'year'])['AverageTemperature'].mean().reset_index()
yc = {}
for country, g in yearly.groupby('Country'):
    pts = [[int(y), round(float(t), 2)] for y, t in zip(g['year'], g['AverageTemperature'])]
    if len(pts) >= 20:
        yc[country] = pts
json.dump(yc, open(f"{DATA}/yearly_by_country.json", "w"))
print("countries:", len(yc))

# Pakistan model (same as the project notebook: Model 2, train 1950-2000)
pak_y = yearly[yearly['Country'] == 'Pakistan']
train = pak_y[(pak_y['year'] >= 1950) & (pak_y['year'] <= 2000)]
test = pak_y[(pak_y['year'] >= 2001) & (pak_y['year'] <= 2013)]
slope, intercept = np.polyfit(train['year'], train['AverageTemperature'], 1)
fut = {str(y): round(float(slope * y + intercept), 2) for y in (2014, 2020, 2030, 2040, 2050)}
model = {
    "slope": float(slope), "intercept": float(intercept),
    "test_years": [[int(y), round(float(a), 2), round(float(slope * y + intercept), 2)]
                   for y, a in zip(test['year'], test['AverageTemperature'])],
    "forecasts": fut,
}
json.dump(model, open(f"{DATA}/pakistan_model.json", "w"))
print("forecasts:", fut)

# Anomalies (alerts page)
an = pd.read_csv(f"{SRC}/outputs/pakistan_anomalies.csv")
alerts = [[str(d)[:10], round(float(a), 2), round(float(b), 2), round(float(x), 2)]
          for d, a, b, x in zip(an['dt'], an['AverageTemperature'], an['baseline_temp'], an['diff'])]
json.dump(alerts, open(f"{DATA}/alerts.json", "w"))
per_year = an.groupby('year').size()
json.dump({str(int(k)): int(v) for k, v in per_year.items()}, open(f"{DATA}/anomalies_per_year.json", "w"))
print("alerts:", len(alerts))

# CO2 correlation
co2 = pd.read_csv(f"{SRC}/data/EarthScape_CO2_companion_1959_2025.csv")
json.dump([[int(y), float(c), float(t)] for y, c, t in zip(co2['Year'], co2['CO2_ppm'], co2['LandAverageTemperature'])],
          open(f"{DATA}/co2.json", "w"))
print("correlation:", round(float(co2['CO2_ppm'].corr(co2['LandAverageTemperature'])), 4))
print("data files:", sorted(os.listdir(DATA)))
