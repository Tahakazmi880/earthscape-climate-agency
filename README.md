# EarthScape Climate Agency - Developer Documentation

eProject: Big Data - EarthScape Climate Agency (Aptech ADSE, Term 6)
Submitted by: Taha Kazmi (student1514118), Centre ACE-PK-KARACHI-2-NORTH NAZIMABAD

## What the system does
A Flask web application that stores, explores and analyses climate data:
login with roles (Administrator, Analyst), a dashboard with interpretation,
a data explorer for 242 countries, machine learning results (trend prediction,
anomaly detection, correlation analysis), an alerts page driven by a
configurable threshold, live tools (prediction, anomaly checker, CSV upload
with on-the-spot processing), feedback and support, and a help/FAQ guide.

## Architecture
- app.py: Flask application (routes, authentication, role checks, live APIs).
- prep_data.py: builds the JSON data files in data/ from the cleaned dataset,
  following the MapReduce pattern (split, map, shuffle, reduce) described in
  the project report. HDFS and the Hadoop cluster are covered as design in the
  report; processing runs in Python (pandas) on the same pattern.
- templates/: Jinja2 pages. static/: stylesheet and the Chart.js library.
- data/: JSON files served by the app (yearly temperatures by country,
  Pakistan model, baseline, checked months, alerts, CO2 series, recent ERA5
  observations, feedback store).

## Machine learning workflow (run by the student in Google Colab)
1. Cleaning: EarthScape_Data_Cleaning_Full_Code.py (577,462 rows to 544,811).
2. Trend prediction: EarthScape_Train_Test_Full_Code.py (Linear Regression,
   Model 2 trained on 1950 to 2000 data, test RMSE 0.52 C).
3. Anomaly detection: EarthScape_Anomaly_Detection_Full_Code.py (1951 to 1980
   baseline, threshold 1.5 C, 41 alerts, top anomaly March 2010 at +4.31 C).
4. Correlation: EarthScape_Correlation_Full_Code.py (CO2 vs temperature,
   r = 0.9655).

## Running locally
pip install -r requirements.txt, then python app.py, open http://127.0.0.1:5000
Demo logins: admin / admin123 (Administrator), analyst / analyst123 (Analyst).

## Deployment
Hosted on Vercel from the GitHub repository (Flask preset, app.py at root).
Every push to the main branch redeploys automatically.
