import re
from urllib.parse import urlparse
import socket
import pandas as pd

# URL 경로에서 가장 긴 단어의 길이
def longest_word_path(url):
    path = urlparse(url).path
    words = re.findall(r'\w+', path)
    longest_word_length = max((len(word) for word in words), default=0)
    
    if longest_word_length > 15:
        return 1  # 피싱 사이트일 가능성
    elif longest_word_length > 5:
        return -1  # 의심 사이트
    else:
        return 0  # 정상 사이트

# URL에 포함된 숫자의 비율
def ratio_digits_url(url):
    digits = re.findall(r'\d', url)
    digit_ratio = len(digits) / len(url) if len(url) > 0 else 0.0
    
    if digit_ratio > 0.08:
        return 1  # 피싱 사이트일 가능성
    elif digit_ratio > 0.02:
        return -1  # 의심 사이트
    else:
        return 0  # 정상 사이트

# URL 전체 길이
def length_url(url):
    url_length = len(url)
    if url_length < 54:
        return 0  # 정상
    elif 54 <= url_length <= 75:
        return -1  # 의심
    else:
        return 1  # 피싱

# 호스트 이름 길이
def length_hostname(url):
    hostname = urlparse(url).netloc
    hostname_length = len(hostname)
    
    if hostname_length > 24:
        return 1  # 피싱 사이트
    elif hostname_length > 19:
        return -1  # 의심 사이트
    else:
        return 0  # 정상 사이트

# Raw URL에서 가장 긴 단어의 길이
def longest_words_raw(url):
    raw_url = urlparse(url).path
    words = re.findall(r'\w+', raw_url)
    longest_word_length = max((len(word) for word in words), default=0)
    
    if longest_word_length > 19:
        return 1  # 피싱 사이트일 가능성
    elif longest_word_length > 10:
        return -1  # 의심 사이트
    else:
        return 0  # 정상 사이트

def port_scan(url):
    try:
        # URL에서 도메인(호스트 이름) 추출
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # 도메인에서 포트 번호를 제거
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # 도메인을 IP 주소로 변환
        ip = socket.gethostbyname(domain)
    except (socket.gaierror, IndexError):
        # 도메인 변환 실패 시 -1 반환
        return -1
    except Exception as e:
        return -1 
    
    socket.setdefaulttimeout(2)
    
    # 필수 포트 및 비권장 포트 목록
    essential_ports = [80, 443]
    non_recommended_ports = [21, 22, 23, 445, 1433, 1521, 3306, 3389]
    
    # 포트 상태 기록
    essential_ports_open = True
    non_recommended_ports_closed = True

    for port in essential_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            s.close()
        except (socket.timeout, socket.error):
            essential_ports_open = False
        finally:
            s.close()

    for port in non_recommended_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            s.close()
            non_recommended_ports_closed = False
        except (socket.timeout, socket.error):
            pass
        finally:
            s.close()
    
    # 사이트 정상 여부 판별
    if essential_ports_open and non_recommended_ports_closed:
        return 0  # 정상 사이트
    else:
        return 1  # 피싱 사이트

# URL에 “@” 기호 포함
def having_at_symbol(url):
    return 1 if '@' in url else 0

# “//”를 사용한 리다이렉션
def double_slash_redirecting(url):
    return 1 if '//' in urlparse(url).path else 0

# if __name__ == '__main__':
#     test_url = 'https://bit.ly/xyz123'  # 여기에 테스트할 URL을 넣으세요

#     print('Longest Word in Path:', longest_word_path(test_url))
#     print('Ratio of Digits in URL:', ratio_digits_url(test_url))
#     print('Length of URL:', length_url(test_url))
#     print('Length of Hostname:', length_hostname(test_url))
#     print('Longest Word in Raw URL:', longest_words_raw(test_url))
#     print('Having @ Symbol:', having_at_symbol(test_url))
#     print('Double Slash Redirecting:', double_slash_redirecting(test_url))

# # 데이터프레임 읽기
# df = pd.read_csv('phishing_detection_url_2.csv')

# with concurrent.futures.ThreadPoolExecutor() as executor:
#     df['port_scan'] = list(executor.map(port_scan, df['url']))
    

# # 결과를 CSV 파일로 저장
# df.to_csv('phishing_detection_data_set_2.csv', index=False)

# print("작업이 완료되었습니다.")