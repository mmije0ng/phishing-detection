import whois
import requests
from urllib.parse import urlparse
import datetime

# 특정 웹 페이지가 구글 검색 엔진의 색인에 포함되어 있는지 여부
def google_index(url):
    try:
        response = requests.get(f"https://www.google.com/search?q=site:{urlparse(url).netloc}")
        return 1 if 'No results' not in response.text else 0
    except requests.RequestException:
        return -1  # 의심
    except Exception as e:
        return -1 

# 도메인 이름에 "www"가 포함된 경우
def having_sub_domain(url):
    return 1 if 'www.' in urlparse(url).netloc else 0

# 도메인이 처음 등록된 날짜에서 현재까지의 시간 (도메인 수명)
def age_of_domain(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return -1
        
        age_days = (datetime.datetime.now() - creation_date).days

        return 0 if age_days >= 180 else 1  # 180일(6개월)을 기준으로 설정
    except Exception as e:
        return -1

# Whois 정보를 이용하여 DNS 기록의 존재 여부를 확인
def dns_record(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        
        if domain_info is None or domain_info.status is None:
            return 1  # Whois 정보가 비어 있거나 DNS 기록이 없으므로 피싱 사이트
        
        return 0  # 정상 사이트
    except Exception as e:
        return -1

# 도메인 등록 기간
def domain_registration_length(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return -1

        age_days = (datetime.datetime.now() - creation_date).days
        return age_days
    except Exception as e:
        return -1

# SSL 인증서의 유효성 여부
def ssl_certificate_status(url):
    try:
        response = requests.get(url, timeout=5)
        return 0 if 'https' in response.url else 1
    except requests.RequestException:
        return 1  # 피싱
    except Exception as e:
        return -1

# Google Safe Browsing을 통해 웹사이트의 안전성 확인
def safe_browsing(url):
    API_KEY = 'AIzaSyD2OaMfUyIk8Zq0BOJs_hCoM_WRZEInx1g'
    API_URL = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}'
    
    body = {
        'client': {
            'clientId': 'yourcompany',
            'clientVersion': '1.0.0'
        },
        'threatInfo': {
            'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    
    try:
        response = requests.post(API_URL, json=body)
        if response.status_code == 200:
            result = response.json()
            return 1 if result.get('matches') else 0
        else:
            return -1
    except requests.RequestException:
        return -1
    except Exception as e:
        return -1

# 웹사이트 트래픽 점수 (외부 API 필요)
def web_traffic(url):
    # 외부 API 사용이 필요합니다. 임의의 값을 반환하도록 구현
    return -1  # 의심

# 웹 페이지로 향하는 링크 수 (외부 API 필요)
def links_pointing_to_page(url):
    # 외부 API 사용이 필요합니다. 임의의 값을 반환하도록 구현
    return -1  # 의심

# 통계 보고 (외부 API 필요)
def statistical_report(url):
    # 외부 API 사용이 필요합니다. 임의의 값을 반환하도록 구현
    return -1  # 의심

# 데이터셋에 새로운 피처를 추가하는 함수
def extract_features(url):
    features = {
        "having_Sub_Domain": having_sub_domain(url),
        "SSLfinal_State": ssl_certificate_status(url),
        "Domain_registeration_length": domain_registration_length(url),
        "age_of_domain": age_of_domain(url),
        "DNSRecord": dns_record(url),
        "web_traffic": web_traffic(url),
        "Page_Rank": -1,  # page_rank(url) 가 필요하나, 외부 API 필요
        "Google_Index": google_index(url),
        "Links_pointing_to_page": links_pointing_to_page(url),
        "Statistical_report": statistical_report(url)
    }
    return features

# 예시 URL 리스트
urls = ["http://example.com", "http://phishingsite.com"]

# 각 URL에 대해 피처를 추출하여 데이터프레임 생성
import pandas as pd

data = []
for url in urls:
    features = extract_features(url)
    features['URL'] = url
    data.append(features)

df = pd.DataFrame(data)
print(df)
