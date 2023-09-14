class Keyspace:
    
    space = 0
    space_complete = 0
    
    
    @classmethod
    def increment_space(cls) -> None:
        cls.space += 1
        
    
    @classmethod
    def increment_space_by(cls, increment: int) -> None:
        cls.space += increment
        
        
    @classmethod
    def increment_space_complete(cls) -> None:
        cls.space_complete += 1
        
        
    @classmethod
    def increment_space_complete_by(cls, increment: int) -> None:
        cls.space_complete += increment