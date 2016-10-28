

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()




# Items for Soccer
soccer = Category(user_id=1, name="Soccer")

session.add(soccer)
session.commit()

soccer_balls = Item(user_id=1, name="Soccer Balls", description="An inflated ball used in playing soccer.",
                        category=soccer)

session.add(soccer_balls)
session.commit()


soccer_goals = Item(user_id=1, name="Soccer Goals",
                        description="""A great training tool for young soccer player.""",
                        category=soccer)

session.add(soccer_goals)
session.commit()


# Items for Basketball
basketball = Category(user_id=1, name="Basketball")

session.add(basketball)
session.commit()

basketball_shoes = Item(user_id=1, name="Basketball Shoes", description="Shoes to wear when playing basketball.",
                            category=basketball)

session.add(basketball_shoes)
session.commit()

basketball_hoop = Item(user_id=1, name="Basketball Hoop",
                        description="A basketball hoop.",
                        category=basketball)

session.add(basketball_hoop)
session.commit()


# Items for Baseball
baseball = Category(user_id=1, name="Baseball")

session.add(baseball)
session.commit()

baseball_bats = Item(user_id=1, name="Baseball Bats",
                        description="A baseball bat.",
                        category=baseball)

session.add(baseball_bats)
session.commit()


baseball_gloves = Item(user_id=1, name="Baseball Gloves",
                            description="A pair of baseball gloves.",
                            category=baseball)

session.add(baseball_gloves)
session.commit()

# Items for Snowboarding
snowboarding = Category(user_id=1, name="Snowboarding")

session.add(snowboarding)
session.commit()


gloves = Item(user_id=1, name="Snowboarding Gloves",
                description="A pair of snowboarding gloves.",
                category=snowboarding)

session.add(gloves)
session.commit()


snowboards = Item(user_id=1, name="Snowboards",
                    description="""Best for any terrain and conditions.""",
                    category=snowboarding)

session.add(snowboards)
session.commit()

print "added category items!"