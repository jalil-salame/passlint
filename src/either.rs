pub enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> Either<L, R> {
    #[inline]
    pub fn map<T, U>(self, f: impl FnOnce(L) -> T, g: impl FnOnce(R) -> U) -> Either<T, U> {
        match self {
            Either::Left(l) => Either::Left(f(l)),
            Either::Right(r) => Either::Right(g(r)),
        }
    }

    #[inline]
    pub fn map_left<T>(self, f: impl FnOnce(L) -> T) -> Either<T, R> {
        self.map(f, std::convert::identity)
    }

    #[inline]
    pub fn map_right<T>(self, f: impl FnOnce(R) -> T) -> Either<L, T> {
        self.map(std::convert::identity, f)
    }
}

impl<T> From<Option<T>> for Either<T, ()> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(v) => Self::Left(v),
            None => Self::Right(()),
        }
    }
}

impl<T, R> From<Result<T, R>> for Either<T, R> {
    fn from(value: Result<T, R>) -> Self {
        match value {
            Ok(l) => Self::Left(l),
            Err(r) => Self::Right(r),
        }
    }
}

impl<T, R> From<Either<T, R>> for Result<T, R> {
    fn from(value: Either<T, R>) -> Self {
        match value {
            Either::Left(l) => Self::Ok(l),
            Either::Right(r) => Self::Err(r),
        }
    }
}

impl<L, R, CL, CR> Extend<Either<L, R>> for (CL, CR)
where
    CL: Extend<L>,
    CR: Extend<R>,
{
    fn extend<T: IntoIterator<Item = Either<L, R>>>(&mut self, iter: T) {
        for either in iter {
            match either {
                Either::Left(l) => self.0.extend(std::iter::once(l)),
                Either::Right(r) => self.1.extend(std::iter::once(r)),
            };
        }
    }
}

impl<L, R, CL, CR> FromIterator<Either<L, R>> for (CL, CR)
where
    CL: FromIterator<L>,
    CR: FromIterator<R>,
{
    fn from_iter<T: IntoIterator<Item = Either<L, R>>>(iter: T) -> Self {
        let mut left = vec![];
        let mut right = vec![];
        for either in iter {
            match either {
                Either::Left(l) => left.push(l),
                Either::Right(r) => right.push(r),
            }
        }
        (CL::from_iter(left), CR::from_iter(right))
    }
}
