from .base_check import BaseCheck
from datetime import datetime
from typing import List, Dict

class CloudTrailManagementEventsCheck(BaseCheck):
    async def check(self) -> List[Dict]:
        cloudtrail = self.session.client('cloudtrail')
        results = []
        raw = []
        
        try:
            trails = cloudtrail.describe_trails()['trailList']
            
            if not trails:
                return {'results': results, 'raw': raw, 'guideline_id': 26}
            
            for trail in trails:
                trail_name = trail['Name']
                trail_arn = trail['TrailARN']
                
                try:
                    # 추적의 이벤트 선택기 조회
                    event_selectors = cloudtrail.get_event_selectors(TrailName=trail_arn)
                    
                    raw.append({
                        'trail_name': trail_name,
                        'trail_arn': trail_arn,
                        'event_selectors': event_selectors,
                        'trail_data': trail
                    })
                    
                    has_incomplete_logging = False
                    api_activity_settings = []
                    
                    # 이벤트 선택기에서 관리 이벤트 확인
                    for selector in event_selectors.get('EventSelectors', []):
                        read_write_type = selector.get('ReadWriteType', 'All')
                        include_management_events = selector.get('IncludeManagementEvents', True)
                        
                        api_activity_settings.append({
                            'read_write_type': read_write_type,
                            'include_management_events': include_management_events
                        })
                        
                        # 관리 이벤트가 포함되고 ReadWriteType이 All이 아닌 경우
                        if include_management_events and read_write_type != 'All':
                            has_incomplete_logging = True
                    
                    if has_incomplete_logging:
                        results.append(self.get_result(
                            '취약', trail_name,
                            f"CloudTrail {trail_name}의 관리 이벤트 API 활동이 ALL이 아닌 {read_write_type}로만 설정되어 있습니다.",
                            {
                                'trail_name': trail_name,
                                'api_activity_settings': api_activity_settings,
                                'has_complete_logging': False
                            }
                        ))
                    else:
                        results.append(self.get_result(
                            '양호', trail_name,
                            f"CloudTrail {trail_name}의 관리 이벤트 API 활동이 적절히 설정되어 있습니다.",
                            {
                                'trail_name': trail_name,
                                'api_activity_settings': api_activity_settings,
                                'has_complete_logging': True
                            }
                        ))
                        
                except Exception as trail_error:
                    results.append(self.get_result('ERROR', trail_name, str(trail_error)))
                        
        except Exception as e:
            results.append(self.get_result('ERROR', 'N/A', str(e)))
        
        return {'results': results, 'raw': raw, 'guideline_id': 26}