import Sauce from "../models/SauceModel.js";
import fs from "fs";

/***************************************************CRUD*********************************** */
export const createSauce = (req, res, next) => {
  const sauceObject = JSON.parse(req.body.sauce);
  delete sauceObject._id;
  //creation of a new instance of the sauce object
  const sauce = new Sauce({
    //...copy of the body of the request
    ...sauceObject,
    //generate image url
    imageUrl: `${req.protocol}://${req.get("host")}/images/${
      req.file.filename
    }`,
  });
  //save in database / send request status
  sauce
    .save()
    .then(() => res.status(201).json({ message: "Registered object !" }))
    .catch((error) =>
      res.status(400).json({ message: "Unregistered object !" })
    );
};

/***********************find () returns all sauces****************************/
export const getAllSauce = (req, res, next) => {
  Sauce.find()
    .then((sauces) => res.status(200).json(sauces))
    .catch((error) =>
      res.status(400).json({ message: "Unregistered object!" })
    );
};

/*return of a single sauce (by retrieving verif if the: _id === req.params.id)*/
export const getSauceUnity = (req, res, next) => {
  Sauce.findOne({ _id: req.params.id })
    .then((sauce) => res.status(200).json(sauce))
    .catch((error) =>
      res.status(404).json({ message: "Unregistered object !" })
    );
};

/****************************sauce modification********************************/
export const modifSauce = (req, res, next) => {
  const sauceObjet = req.file
    ? {
        ...JSON.parse(req.body.sauce),
        imageUrl: `${req.protocol}://${req.get("host")}/images/${
          req.file.filename
        }`,
      }
    : { ...req.body };
  //method updateOne() 1er argument = object  modify/verifSiId=idOk
  Sauce.updateOne({ _id: req.params.id }, { ...sauceObjet, _id: req.params.id })
    .then(() => res.status(200).json({ message: "Modified sauce !" }))
    .catch((error) => res.status(400).json({ error }));
};

/***********delete sauce by verifying that the user has the correct username******/
export const deleteSauce = (req, res, next) => {
  Sauce.findOne({ _id: req.params.id })
    .then((sauce) => {
      const filename = sauce.imageUrl.split("/images/")[1]; //extract name of file to delete
      fs.unlink(`images/${filename}`, () => {
        Sauce.deleteOne({ _id: req.params.id })
          .then(() => res.status(200).json({ message: "Deleted object !" }))
          .catch((error) => res.status(400).json({ error }));
      });
    })

    .catch((error) => res.status(500).json({ error }));
};

/**********************************************likedSauce and dislikedSauce***** */
export const likeSauces = (req, res) => {
  //If the customer likes this sauce $inc=opérateur incrémente
  if (req.body.like === 1) {
    Sauce.findOneAndUpdate(
      { _id: req.params.id },
      { $inc: { likes: 1 }, $push: { usersLiked: req.body.userId } }
    )
      .then(() => res.status(200).json({ message: "Like added !" }))
      .catch((error) => res.status(400).json({ error }));
    /* If the customer dislike this sauce */
  } else if (req.body.like === -1) {
    try {
      Sauce.findOneAndUpdate(
        { _id: req.params.id },
        { $inc: { dislikes: 1 }, $push: { usersDisliked: req.body.userId } }
      )
        .then(() => res.status(200).json({ message: "Dislike added!" }))
        .catch((error) => res.status(400).json({ error }));
    } catch (e) {
      console.log(e);
    }
    /* If the customer cancels their choice */
  } else {
    Sauce.findOne({ _id: req.params.id }).then((resultat) => {
      if (resultat.usersLiked.includes(req.body.userId)) {
        Sauce.findOneAndUpdate(
          { _id: req.params.id },
          { $inc: { likes: -1 }, $pull: { usersLiked: req.body.userId } }
        )
          .then(() => res.status(200).json({ message: "like removed !" }))
          .catch((error) => res.status(400).json({ error }));
      } else if (resultat.usersDisliked.includes(req.body.userId)) {
        Sauce.findOneAndUpdate(
          { _id: req.params.id },
          { $inc: { dislikes: -1 }, $pull: { usersDisliked: req.body.userId } }
        )
          .then(() => res.status(200).json({ message: "dislike removed !" }))
          .catch((error) => res.status(400).json({ error }));
      }
    });
  }
};
