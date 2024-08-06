from queue import Full
import whois
import requests
from urllib.parse import urlparse  # urlparse 임포트
import datetime
import requests
import config


# 위협 유형 리스트
THREAT_TYPES = [
    "THREAT_TYPE_UNSPECIFIED",
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION"
]

# 특정 웹 페이지가 구글 검색 엔진의 색인에 포함되어 있는지 여부
def google_index(url):
    try:
        response = requests.get(f"https://www.google.com/search?q=site:{urlparse(url).netloc}")
        return 1 if 'No results' not in response.text else 0
    except requests.RequestException:
        return -1  # 의심
    except Exception as e:
        return -1 

# def page_rank(url):
#     try:
#         # Google PageRank는 현재 공식적으로 제공되지 않음
#         return -1  # 의심
#     except Exception:
#         return -1  # 의심

# def web_traffic(url):
#     try:
#         # 웹 트래픽 정보는 외부 API를 통해 조회해야 함
#         return -1  # 의심
#     except Exception:
#         return -1  # 의심

# 도메인 이름에 "www"가 포함된 경우
# 포함되지 않으면 피싱
def nb_www(url):
    return 1 if 'www.' not in urlparse(url).netloc else 0

# 도메인이 처음 등록된 날짜에서 현재까지의 시간
def domain_age(url):
    try:
        # URL에서 도메인 추출
        domain = urlparse(url).netloc
        
        # 도메인 정보 가져오기
        domain_info = whois.whois(domain)
        
        # 도메인의 생성일 추출
        creation_date = domain_info.creation_date
        
        # 생성일이 리스트로 반환되는 경우 첫 번째 항목 선택
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # 생성일이 없는 경우 오류로 간주
        if creation_date is None:
            return -1
        
        # 현재 날짜와 생성일 사이의 차이 계산
        age_days = (datetime.datetime.now() - creation_date).days
        
        # 평균 도메인 연령에 따라 기준을 조정
        # 피싱 사이트의 평균 도메인 연령이 3031일이므로, 이를 기준으로 판단
        # 3031일 이상인 경우 정상 사이트로 간주
        if age_days >= 3031:
            return 0  # 정상 사이트
        else:
            return 1  # 피싱 사이트
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1  # 오류 발생 시 -1 반환

# Whois 정보를 이용하여 DNS 기록의 존재 여부를 확인하고 피싱 사이트 여부를 판별
def dns_record(url):
    try:
        # URL에서 호스트명 추출
        domain = urlparse(url).netloc
        
        # Whois 정보 조회
        domain_info = whois.whois(domain)
        
        # Whois 정보에서 DNS 기록 확인
        if domain_info is None or domain_info.status is None:
            return 1  # Whois 정보가 비어 있거나 DNS 기록이 없으므로 피싱 사이트
        
        # 정상적으로 Whois 정보가 존재하는 경우
        return 0  # 정상 사이트
    
    except Exception as e:
        print(f"Whois 조회 중 오류 발생: {e}")
        return -1  # Whois 조회 중 오류 발생 시 -1 반환

# 도메인 등록 기간
def domain_registration_period(url):
    try:
        # URL에서 호스트명 추출
        domain = urlparse(url).netloc
        
        # Whois 정보 조회
        domain_info = whois.whois(domain)
        
        # 도메인 등록 날짜 확인
        if domain_info.creation_date is None:
            return -1  # Whois 정보가 없는 경우
        
        # 등록 날짜가 리스트일 수 있으므로 첫 번째 날짜를 사용
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date
        
        # 도메인 등록 기간 계산
        if isinstance(creation_date, datetime.datetime):
            age_days = (datetime.datetime.now() - creation_date).days
        else:
            return -1  # 등록 날짜가 올바르지 않은 형식인 경우
        
        # 도메인 등록 기간 기준에 따른 피싱 사이트 판별
        if age_days < 180:  # 6개월 미만
            return 1  # 피싱 사이트
        else:
            return 0  # 정상 사이트
    
    except Exception as e:
        print(f"Whois 조회 중 오류 발생: {e}")
        return -1  # Whois 조회 중 오류 발생 시 -1 반환

def ssl_certificate_status(url):
    try:
        response = requests.get(url, timeout=5)
        return 0 if 'https' in response.url else 1
    except requests.RequestException:
        return 1  # 피싱
    except Exception as e:
        return -1 

def safe_browsing(url):
    # Google Safe Browsing API를 사용하여 결과를 가져와야 함
    
    # Google Safe Browsing API에 요청할 데이터
    # 요청 본문 생성
    body = {
        'client': {
            'clientId': 'yourcompany',
            'clientVersion': '1.0.0'
        },
        'threatInfo': {
            'threatTypes': [THREAT_TYPES],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    
    try:
        response = requests.post(config.API_URL, json=body)
        # 결과 처리 (예: 피싱 또는 멀웨어 탐지 여부)
        if response.status_code == 200:
            result = response.json()
            # 결과에 따라 반환
            return 1 if result.get('matches') else 0
        else:
            return -1  # 요청 실패
    except requests.RequestException:
        return -1  # 요청 실패
    except Exception as e:
        return -1 