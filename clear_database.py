from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


# session.delete(User)
# session.commit()

# session.delete(Category)
# session.commit()

# session.delete(Item)
# session.commit()


User.__table__.drop()
Item.__table__.drop()
Category.__table__.drop()







