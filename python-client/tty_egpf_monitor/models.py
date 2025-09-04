"""
Data models for TTY eBPF Monitor client.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass
class Port:
    """Represents a monitored TTY port."""
    idx: int
    device: str
    baudrate: Optional[int] = None
    log_path: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Port':
        """Create Port from daemon response dictionary."""
        return cls(
            idx=data['idx'],
            device=data['dev'],
            baudrate=data.get('baudrate'),
            log_path=data.get('log_path')
        )


@dataclass 
class LogEntry:
    """Represents a single log entry from the TTY monitor."""
    timestamp: datetime
    event_type: str
    process: str
    direction: Optional[str] = None
    data: Optional[bytes] = None
    baudrate: Optional[int] = None
    ioctl_cmd: Optional[int] = None
    raw_line: str = ""
    
    @classmethod
    def parse_simple_log(cls, line: str) -> 'LogEntry':
        """Parse a simple format log line."""
        import re
        
        # Parse format: [04.09.25 14:52:46.874] WRITE: picocom APP->DEV "data"
        pattern = r'\[(\d{2}\.\d{2}\.\d{2}) (\d{2}:\d{2}:\d{2}\.\d{3})\] (\w+): (\w+)(?: (APP->DEV|DEV->APP))?(?: (.*))?'
        match = re.match(pattern, line.strip())
        
        if not match:
            # Fallback for other formats like MODE_CHANGE
            pattern2 = r'\[(\d{2}\.\d{2}\.\d{2}) (\d{2}:\d{2}:\d{2}\.\d{3})\] (\w+): (.*)'
            match2 = re.match(pattern2, line.strip())
            if match2:
                date_str, time_str, event_type, details = match2.groups()
                timestamp = cls._parse_datetime(date_str, time_str)
                return cls(
                    timestamp=timestamp,
                    event_type=event_type,
                    process=details.split()[0] if details else "",
                    raw_line=line.strip()
                )
            
            # If no pattern matches, return basic entry
            return cls(
                timestamp=datetime.now(),
                event_type="UNKNOWN",
                process="",
                raw_line=line.strip()
            )
        
        date_str, time_str, event_type, process, direction, data_part = match.groups()
        timestamp = cls._parse_datetime(date_str, time_str)
        
        # Parse data if present (quoted string with escapes)
        data = None
        if data_part and data_part.startswith('"') and data_part.endswith('"'):
            data_str = data_part[1:-1]  # Remove quotes
            # Decode escape sequences
            data = cls._decode_escaped_data(data_str)
        
        return cls(
            timestamp=timestamp,
            event_type=event_type,
            process=process,
            direction=direction,
            data=data,
            raw_line=line.strip()
        )
    
    @staticmethod
    def _parse_datetime(date_str: str, time_str: str) -> datetime:
        """Parse dd.mm.yy HH:MM:SS.mmm format."""
        from datetime import datetime
        
        # Parse date: dd.mm.yy
        day_str, month_str, year_str = date_str.split('.')
        year_int = int('20' + year_str)  # Convert yy to 20yy
        
        # Parse time: HH:MM:SS.mmm
        time_part, ms_part = time_str.split('.')
        hour_str, minute_str, second_str = time_part.split(':')
        
        return datetime(
            year=year_int,
            month=int(month_str),
            day=int(day_str),
            hour=int(hour_str),
            minute=int(minute_str),
            second=int(second_str),
            microsecond=int(ms_part) * 1000  # Convert ms to microseconds
        )
    
    @staticmethod
    def _decode_escaped_data(data_str: str) -> bytes:
        """Decode escaped data string to bytes."""
        result = bytearray()
        i = 0
        while i < len(data_str):
            if data_str[i] == '\\' and i + 1 < len(data_str):
                if data_str[i + 1] == 'x' and i + 3 < len(data_str):
                    # Hex escape: \xNN
                    try:
                        hex_val = int(data_str[i+2:i+4], 16)
                        result.append(hex_val)
                        i += 4
                    except ValueError:
                        result.append(ord(data_str[i]))
                        i += 1
                elif data_str[i + 1] in ['\\', '"']:
                    # Escaped backslash or quote
                    result.append(ord(data_str[i + 1]))
                    i += 2
                else:
                    result.append(ord(data_str[i]))
                    i += 1
            else:
                result.append(ord(data_str[i]))
                i += 1
        
        return bytes(result)
