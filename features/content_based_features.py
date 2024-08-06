import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# 웹 페이지 내의 하이퍼링크 수
def nb_hyperlinks(url):
    try:
        response = requests.get(url)
        response.encoding = response.apparent_encoding  # 문자 인코딩 자동 감지 및 설정
        
        soup = BeautifulSoup(response.content, 'lxml')
        
        link_count = len(soup.find_all('a'))
        
        # 하이퍼링크 개수에 따른 피싱 사이트 판별
        if link_count > 144:
            return 0  
        elif link_count > 30:
            return -1  
        else:
            return 1
    except requests.RequestException:
        return -1  # 요청 실패 시 의심
    except Exception as e:
        return -1 

#  웹 페이지에서 외부 하이퍼링크의 비율
def ratio_extHyperlinks(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'lxml')
        links = soup.find_all('a')
        total_links = len(links)
        
        if total_links == 0:
            return 0  # 하이퍼링크가 없는 경우 비율 0 반환
        
        current_domain = urlparse(url).netloc
        ext_links = sum(1 for link in links if urlparse(link.get('href')).netloc != current_domain)
        ext_link_ratio = ext_links / total_links
        
        # 외부 하이퍼링크 비율에 따른 피싱 사이트 판별
        if ext_link_ratio > 0.3:  
            return 1  # 피싱 사이트
        elif ext_link_ratio > 0.25: 
            return -1  # 의심 사이트
        else:
            return 0  # 정상 사이트
    except requests.RequestException:
        return -1  # 요청 실패 시 의심
    except Exception as e:
        return -1 

# 앵커 텍스트(링크에 사용되는 텍스트)가 안전한지 여부
def safe_anchor(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'lxml')
        anchors = soup.find_all('a')
        if any('login' in anchor.get_text().lower() for anchor in anchors):
            return 1  # 피싱
    except requests.RequestException:
        return -1  # 의심
    except Exception as e:
        return -1 
    return 0  # 정상


# 우클릭 방지 여부
def disable_right_click(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'lxml')
        script_tags = soup.find_all('script')
        for script in script_tags:
            if 'oncontextmenu' in script.get_text():
                return 1  # 피싱
    except requests.RequestException:
        return -1  # 의심
    except Exception as e:
        return -1 
    return 0  # 정상

# HTML 소스코드에 도메인 이름이 포함되어 있는지 여부
def domain_in_source(url):
    try:
        domain = urlparse(url).netloc
        response = requests.get(url)
        if domain in response.text:
            return 0  # 정상
    except requests.RequestException:
        return -1  # 의심
    except Exception as e:
        return -1 
    return 1  # 피싱

# 팝업 창에 텍스트 필드가 포함되어 있는지 여부
def popup_window_text(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'lxml')
        forms = soup.find_all('form')
        # 텍스트 필드 포함 시
        if any(form.find('input', {'type': 'text'}) for form in forms):
            return 1  # 피싱
    except requests.RequestException:
        return -1  # 의심
    except Exception as e:
        return -1 
    return 0  # 정상

# iframe 사용 여부
def iFrame_redirection(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'lxml')
        if soup.find_all('iframe'): # iframe 사용 시
            return 1  # 피싱
    except requests.RequestException:
        return -1  # 의심
    except Exception as e:
        return -1 
    return 0  # 정상

def IP_usage(url):
    domain = urlparse(url).netloc
    return 1 if domain.replace('.', '').isdigit() else 0

# if __name__ == '__main__':
#     test_url = 'https://bit.ly/xyz123'  # 여기에 테스트할 URL을 넣으세요

#     print('Number of Hyperlinks:', nb_hyperlinks(test_url))
#     print('Ratio of External Hyperlinks:', ratio_extHyperlinks(test_url))
#     print('Safe Anchor Text:', safe_anchor(test_url))
#     print('Disable Right Click:', disable_right_click(test_url))
#     print('Domain in Source:', domain_in_source(test_url))
#     print('Popup Window with Text Field:', popup_window_text(test_url))
#     print('iFrame Redirection:', iFrame_redirection(test_url))
#     print('IP Usage:', IP_usage(test_url))
