# pyvt

pyvt is a Python wrapper for VirusTotal URL API, as well as a CLI program!
You can utilize pyvt's functionality either by using it as a command line interface program (`cli.py`), or utilize it throughout your code using `Analyzer` & `Result` instantiations and methods.

Please note that the CLI program embarks **cache mechanism** to optimize performance and data retrieval.

## CLI
### Arguments
* `url -- 1 or more URLs, separated with a whitespace`
* `-k -- followed by a VT API key`
	* (Note: the API key can be either provided as an argument or as an environmental variable: 
`self._apikey = apikey or os.environ["VT_KEY"]`
* `-s -- URL force-scan`
* `-a -- cache age, defaults to 182 days (~6 months)`
* `-v -- verbose performance (developer prints)`
### Usage examples
Non-cached URLs:
```python
python3 cli.py https://youtube.com/ https://twitter.com/
>> URL: https://twitter.com/, analysis date: 28-01-2023, result: ('harmless', '87.78%'), source: api
>> URL: https://youtube.com/, analysis date: 25-01-2023, result: ('harmless', '88.89%'), source: api
```
Cached URLs:
```python
python3 cli.py https://canva.com/ https://google.com/ https://facebook.com/
>> URL: https://canva.com/, analysis date: 28-01-2023, result: ('harmless', '87.78%'), source: cache
>> URL: https://facebook.com/, analysis date: 28-01-2023, result: ('harmless', '88.89%'), source: cache
>> URL: https://google.com/, analysis date: 28-01-2023, result: ('harmless', '88.89%'), source: cache
```
Non-cached URL w/ default cache age, on January, 28th, 2023:
```python
python3 cli.py https://canva.com/
>> URL: https://canva.com/, analysis date: 25-01-2023, result: ('harmless', '87.78%'), source: api
```
Non-cached URL w/ '1 day' cache age, on January, 28th, 2023:
```python
python3 cli.py https://canva.com/ -a 1
>> URL: https://canva.com/, analysis date: 28-01-2023, result: ('harmless', '87.78%'), source: api
```
## Analyzer():
Instantiate an Analyzer class instance by passing through cache directory path, API key and cache age, respectively.
```python
analyzer = Analyzer(cache_dir='cache', apikey='KEY', age=3)
```
### Analyzer URL
Analyzes a base64 URL and returns a Result instance.
```python
analysis = analyzer.analyze(urls="https://google.com")
print(analysis)
# Result()'s __str__ implementation:
>> URL: https://google.com, analysis date: 28-01-2023, result: ('harmless', '88.89%'), source: api
```
### Scan URL
Scans provided URL and returns its scan ID from VT API (`response.json()["data"]["id"]`).
```python
scan = analyzer.scan('https://twitter.com/')
print(scan)
>> "u-2fa5e3f40150278f9592879390c316db8c7bc8eb6b850c1e0a5a36836e6952b6-16749431"
```
### Full Scan URL:
Re-scans and re-analyzes according to the new scan ID. Good for up-to-date analysis, regardless of cache maximum age.
```python
analysis = analyzer.full_scan(url='https://google.com')
print(analysis)
>> URL: https://google.com, analysis date: 28-01-2023, result: ('harmless', '88.89%'), source: api
```
## Result():
Results stored in cache.pickle are instances of Result, thus containing vital meta data that can be accessed through simple code lines.
### url: str
```python
print(analysis.url)
>> 'https://google.com'
```
### source: str
```python
print(analysis.source)
>> 'api'
```
### timestamp: float

```python
print(analysis.ts)
>> 1674943031	# Epoch/Unix timestamp
```
### result: tuple
```python
print(analysis.result)
>> ('harmless', '88.89%')
```